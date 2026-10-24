<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Runner;

use App\Builds\BuildConfig;
use App\Builds\Stage;

/**
 * §8.5.9's network-namespace warden: the nftables backstop, and the proxy
 * address it pins.
 *
 * > "Egress MUST default to an allowlisted CONNECT proxy … **plus an
 * > nftables backstop inside the build network namespace** so proxy bypass
 * > still fails at layer 3."
 *
 * 🛑 **Why there is a second container at all.** `nft` needs
 * `CAP_NET_ADMIN`; §8.5.8 requires the build container to drop every
 * capability. A container cannot install the rules that constrain it
 * without also being able to remove them. So the warden is started first
 * **with** the capability, installs the ruleset into its own network
 * namespace and then runs `sleep`; the build container joins that namespace
 * with `--network container:<warden>` and no capabilities at all.
 *
 * 🛑 **What the backstop closes that `internal: true` does not.** An
 * internal Docker network has no route *off* the host — but it has a route
 * *across* itself, and two organisations' builds share it. Without the
 * ruleset, one build can open a socket to another's. Measured in ADR 0011:
 * with it, a sibling container is unreachable while the proxy at its one
 * port is not.
 *
 * In `App\Builds\Runner` because it names a container runtime, which
 * `ArchitectureTest::test_only_the_runner_namespace_names_a_container_runtime`
 * permits in exactly one namespace (§8.5.13).
 */
final class Warden
{
    /** Marks the proxy container so the runner never has to guess its name. */
    public const PROXY_LABEL_KEY = 'docup.role';

    public function __construct(
        private readonly Docker $docker = new Docker,
    ) {}

    /**
     * The egress proxy's address on the sandbox network, or null when there
     * is no proxy running.
     *
     * 🛑 Found by **label**, never by container name. A compose project
     * renamed from `docup` changes every container's name, and a runner that
     * looked for `docup-proxy-1` would then find nothing — and a warden told
     * there is no proxy installs a ruleset with no egress at all. The
     * failure would be every build losing its network with a green
     * `docker ps`, which is the exact shape ADR 0011 records getting wrong
     * once already.
     */
    public function proxyAddress(): ?string
    {
        $label = BuildConfig::string('sandbox.proxy_label', self::PROXY_LABEL_KEY.'=egress-proxy');
        $network = BuildConfig::string('sandbox.network', 'docup_sandboxes');

        [$status, $output] = $this->docker->capture([
            'ps', '--quiet', '--filter', 'label='.$label,
        ]);

        if ($status !== 0) {
            return null;
        }

        $id = trim(explode("\n", trim($output))[0]);

        if ($id === '') {
            return null;
        }

        [$status, $address] = $this->docker->capture([
            'inspect', '--format', '{{ with (index .NetworkSettings.Networks "'.$network.'") }}{{ .IPAddress }}{{ end }}', $id,
        ]);

        $address = trim($address);

        if ($status !== 0 || filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return null;
        }

        return $address;
    }

    /**
     * Start a warden for one stage and return its container name.
     *
     * 🛑 **The ruleset is verified, not assumed.** The warden prints a
     * marker after `nft -f` succeeds, and this waits for it. ADR 0011
     * records why: the first warden installed nftables at start-up on an
     * internal network with no package index, the install failed, the
     * container stayed up, and the joined build had full access to its
     * siblings while everything looked healthy. A control whose failure
     * mode is "appears to work" has to be observed working.
     *
     * @throws \RuntimeException when the namespace is not provably locked
     */
    public function start(string $buildId, Stage $stage, ?string $proxyAddress): string
    {
        $name = 'docup-warden-'.$buildId.'-'.$stage->value;
        $port = BuildConfig::positiveInt('sandbox.proxy_port', 3128);

        $this->docker->capture(['rm', '--force', $name]);

        $argv = [
            'run', '--detach',
            '--name', $name,
            '--label', ArgvTemplate::OWNER_LABEL,
            '--label', 'docup.build='.$buildId,
            '--network', BuildConfig::string('sandbox.network', 'docup_sandboxes'),

            /*
             * The one capability granted anywhere in the pipeline, to the
             * one container that runs no repository code and holds no
             * credential. Everything else is dropped, including here: a
             * warden needs to write nftables rules and nothing else.
             */
            '--cap-drop', 'ALL',
            '--cap-add', 'NET_ADMIN',
            '--security-opt', 'no-new-privileges',
            '--read-only',
            '--memory', '64m',
            '--memory-swap', '64m',
            '--pids-limit', '16',
            '--env', 'DOCUP_PROXY_PORT='.$port,
            '--env', 'DOCUP_WARDEN_TTL='.(string) BuildConfig::positiveInt('limits.wall_clock_seconds', 1800),
        ];

        if ($proxyAddress !== null) {
            $argv[] = '--env';
            $argv[] = 'DOCUP_PROXY_IP='.$proxyAddress;
        }

        $argv[] = BuildConfig::string('sandbox.warden_image', 'docup/warden:1');

        [$status, $output] = $this->docker->capture($argv);

        if ($status !== 0) {
            throw new \RuntimeException('could not start the sandbox warden: '.trim($output));
        }

        $this->awaitRuleset($name);

        return $name;
    }

    /**
     * How many packets the backstop dropped for this build.
     *
     * 🛑 Read from the ruleset's named counter while the warden is still
     * alive, which is why the runner stops it only after classification.
     * This is the difference between `user.egress_blocked_at_layer3` as a
     * fact and as a guess: from the build's own output, a dropped packet and
     * a package index being down are the same sentence.
     *
     * Zero on any error, because an unreadable counter must not become an
     * accusation.
     */
    public function blockedPackets(string $name): int
    {
        [$status, $output] = $this->docker->capture([
            'exec', $name, 'nft', 'list', 'counter', 'inet', 'docup', 'blocked',
        ]);

        if ($status !== 0 || preg_match('/packets\s+(\d+)/', $output, $matches) !== 1) {
            return 0;
        }

        return (int) $matches[1];
    }

    public function stop(string $name): void
    {
        $this->docker->capture(['rm', '--force', $name]);
    }

    /**
     * Wait for the warden's own confirmation that the ruleset is in force.
     *
     * Two seconds is generous for a container whose entrypoint is one `nft`
     * call; the cost of being wrong in the other direction is a build with
     * no backstop, so this throws rather than continuing.
     */
    private function awaitRuleset(string $name): void
    {
        $deadline = microtime(true) + 10.0;

        while (microtime(true) < $deadline) {
            [, $logs] = $this->docker->capture(['logs', $name]);

            if (str_contains($logs, 'docup-warden: ruleset installed')) {
                return;
            }

            [, $running] = $this->docker->capture(['inspect', '--format', '{{.State.Running}}', $name]);

            if (trim($running) === 'false') {
                break;
            }

            usleep(100_000);
        }

        [, $logs] = $this->docker->capture(['logs', $name]);
        $this->stop($name);

        throw new \RuntimeException(
            'the sandbox warden did not confirm its nftables ruleset, so the build network '
            .'namespace is not provably isolated (§8.5.9): '.trim(substr($logs, -500)),
        );
    }
}
