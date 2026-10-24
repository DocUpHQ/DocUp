<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Runner;

use App\Builds\BuildConfig;
use App\Builds\Sandbox\EgressMode;
use App\Builds\Sandbox\SandboxPolicy;
use App\Builds\Stage;

/**
 * §8.5.12's boot-time network isolation self-test.
 *
 * > "Network isolation MUST be verified at boot by launching a throwaway
 * > container and asserting that the database, cache and metadata endpoint
 * > are unreachable while a proxied request succeeds. **Startup MUST fail**
 * > if the self-test fails."
 *
 * 🛑 **Both halves, and the second is the one that is easy to drop.** A test
 * that only proved unreachability would pass just as well against a
 * container with no network at all — which is to say it would pass on an
 * installation where every build is broken. "A proxied request succeeds" is
 * what distinguishes an isolated sandbox from a severed one.
 *
 * 🛑 **The proxied request is a raw CONNECT handshake, not an HTTPS fetch.**
 * The thing under test is whether the proxy will tunnel for a build, and a
 * `curl https://…` answers that only after also depending on a TLS stack, a
 * CA bundle and the origin being up. A `CONNECT host:443` and the
 * `HTTP/1.1 200` that comes back test exactly the layer §8.5.9 governs,
 * using a tool every image already has.
 *
 * The whole test runs as **one container** rather than one per assertion:
 * five container starts at boot would add seconds to every start-up, and
 * the checks share the namespace they are about.
 */
final class IsolationSelfTest
{
    /** Each check prints `<name> <OK|FAIL> <detail>`; this parses that. */
    private const MARKER = 'docup-selftest';

    public function __construct(
        private readonly Docker $cli = new Docker,
        private readonly Warden $warden = new Warden,
    ) {}

    /**
     * Run the self-test and report what happened.
     *
     * Never throws: the caller decides whether a failure refuses a boot or
     * colours a `docup:doctor` line, and an exception here would make the
     * two behave differently for reasons of plumbing.
     */
    public function run(): SelfTestResult
    {
        $proxy = $this->warden->proxyAddress();

        if ($proxy === null) {
            return SelfTestResult::unavailable(
                'no egress proxy is running (nothing carries the label '
                .BuildConfig::string('sandbox.proxy_label', 'docup.role=egress-proxy').'), '
                .'so §8.5.9 has nothing to enforce the allowlist and §8.5.12 cannot be run.',
            );
        }

        /*
         * 🛑 The self-test runs in the placement BUILDS ACTUALLY GET, not
         * in the strictest one available. Under §8.5.11's acknowledged
         * `open` egress there is no warden and no backstop, and a
         * self-test that quietly built one anyway would certify a sandbox
         * no build ever runs in — which is the precise shape of a control
         * that reports success about something it did not check.
         */
        $egress = SandboxPolicy::fromConfig()->egressFor(Stage::Build);
        $id = bin2hex(random_bytes(16));
        $warden = null;

        if ($egress === EgressMode::Allowlist) {
            try {
                $warden = $this->warden->start($id, Stage::Build, $proxy);
            } catch (\RuntimeException $failed) {
                return SelfTestResult::failed(['warden' => [false, $failed->getMessage()]]);
            }
        }

        try {
            [$status, $output] = $this->cli->capture([
                'run', '--rm',
                '--network', match (true) {
                    $warden !== null => 'container:'.$warden,
                    $egress === EgressMode::Open => 'bridge',
                    default => 'none',
                },
                '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges',
                '--read-only',
                '--memory', '64m', '--memory-swap', '64m', '--pids-limit', '32',
                '--label', ArgvTemplate::OWNER_LABEL,
                'busybox:stable',
                'sh', '-c', $this->script($proxy),
            ]);
        } finally {
            if ($warden !== null) {
                $this->warden->stop($warden);
            }
        }

        if ($status !== 0 && ! str_contains($output, self::MARKER)) {
            return SelfTestResult::failed([
                'container' => [false, 'the self-test container did not run: '.trim(substr($output, -300))],
            ]);
        }

        return SelfTestResult::fromOutput($output, self::MARKER);
    }

    /**
     * The checks, as one busybox script.
     *
     * 🛑 Every reachability check is written so that **the failure to
     * connect is the pass**. That is the opposite of the usual shape and it
     * is easy to invert by accident, so each line states its own verdict
     * rather than leaving a caller to interpret an exit code.
     */
    private function script(string $proxy): string
    {
        $port = BuildConfig::positiveInt('sandbox.proxy_port', 3128);
        $lines = [];

        /** @var array<string, mixed> $forbidden */
        $forbidden = BuildConfig::map('sandbox.self_test.forbidden');

        foreach ($forbidden as $name => $target) {
            if (! is_string($target) || ! str_contains($target, ':')) {
                continue;
            }

            [$host, $hostPort] = explode(':', $target, 2);
            $host = preg_replace('/[^A-Za-z0-9._-]/', '', $host) ?? '';
            $hostPort = preg_replace('/\D/', '', $hostPort) ?? '';
            $label = preg_replace('/[^a-z_]/', '', strtolower($name)) ?? 'target';

            if ($host === '' || $hostPort === '') {
                continue;
            }

            /*
             * 🛑 `-w 3`, and the timeout is load-bearing. An unreachable
             * address behind a DROP rule never answers at all, so a `nc`
             * with no timeout would hang the boot of the installation this
             * check is protecting.
             */
            $lines[] = sprintf(
                'if nc -w 3 %s %s </dev/null >/dev/null 2>&1; then echo "%s %s FAIL reachable"; '
                .'else echo "%s %s OK unreachable"; fi',
                $host, $hostPort, self::MARKER, $label, self::MARKER, $label,
            );
        }

        // §8.5.12's other half: a proxied request must succeed.
        $lines[] = sprintf(
            'R=$(printf "CONNECT %s HTTP/1.1\\r\\nHost: %s\\r\\n\\r\\n" | nc -w 8 %s %d 2>/dev/null | head -n 1); '
            .'case "$R" in *" 200"*) echo "%s proxy_tunnel OK $R";; *) echo "%s proxy_tunnel FAIL ${R:-no answer}";; esac',
            'pypi.org:443', 'pypi.org:443', $proxy, $port, self::MARKER, self::MARKER,
        );

        /*
         * ...and a host off the allowlist must not. Without this, a proxy
         * misconfigured to allow everything passes §8.5.12 with full marks:
         * the forbidden addresses are blocked at layer 3 regardless, and
         * the tunnel check only asks whether tunnelling works at all.
         */
        $lines[] = sprintf(
            'R=$(printf "CONNECT %s HTTP/1.1\\r\\nHost: %s\\r\\n\\r\\n" | nc -w 8 %s %d 2>/dev/null | head -n 1); '
            .'case "$R" in *" 403"*) echo "%s proxy_allowlist OK refused";; *) echo "%s proxy_allowlist FAIL ${R:-no answer}";; esac',
            'example.invalid:443', 'example.invalid:443', $proxy, $port, self::MARKER, self::MARKER,
        );

        return implode('; ', $lines);
    }
}
