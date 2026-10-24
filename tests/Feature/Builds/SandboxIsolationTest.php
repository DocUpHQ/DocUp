<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Builds\Runner\Docker;
use App\Builds\Runner\IsolationSelfTest;
use App\Builds\Runner\Spool;
use App\Builds\Runner\Warden;
use App\Builds\Stage;
use Illuminate\Support\Facades\Artisan;
use Tests\Support\RequiresBuildImages;
use Tests\TestCase;

/**
 * §8.5.12's boot self-test, and the §11.2 trust zones it checks.
 *
 * > "Network isolation MUST be verified at boot by launching a throwaway
 * > container and asserting that the database, cache and metadata endpoint
 * > are unreachable while a proxied request succeeds. **Startup MUST fail**
 * > if the self-test fails."
 *
 * 🛑 **The second test here is the exit criterion and it is deliberately
 * destructive.** "Startup fails when the self-test container can reach
 * MySQL" cannot be demonstrated by asserting that it currently cannot: that
 * is the first test, and it would pass equally against a self-test that
 * always returned true. So this one *makes* the database reachable — by
 * attaching it to the sandbox network — watches the runner refuse to start,
 * and puts the topology back.
 *
 * Runs in the `runner` container: launching the throwaway container needs
 * the runtime socket, which §8.5.13 gives to exactly one process.
 */
final class SandboxIsolationTest extends TestCase
{
    use RequiresBuildImages;

    /** The shipped topology passes, which is the baseline for everything below. */
    public function test_the_shipped_topology_passes_the_self_test(): void
    {
        $this->requireSandbox();

        $result = (new IsolationSelfTest)->run();

        $this->assertTrue($result->passed, $result->summary);

        foreach (['database', 'cache', 'metadata', 'proxy_tunnel', 'proxy_allowlist'] as $check) {
            $this->assertArrayHasKey($check, $result->checks, '§8.5.12 did not run the '.$check.' check');
            $this->assertTrue($result->checks[$check][0], $check.' failed: '.$result->checks[$check][1]);
        }
    }

    /**
     * 🛑 Phase 07's exit criterion: "Startup fails when the self-test
     * container can reach MySQL."
     *
     * 🛑 **Making MySQL reachable takes more than attaching it to the
     * sandbox network, and the reason is itself a result.** The first
     * attempt did exactly that and the self-test still reported the
     * database unreachable — because the warden's nftables ruleset drops
     * every packet that is not bound for the proxy, routable or not. The
     * backstop was doing its job so well that the test could not create
     * the failure it needed. That is defence in depth working, and it is
     * recorded rather than worked around.
     *
     * So this reproduces the configuration where a routable database
     * genuinely is reachable: §8.5.11's acknowledged `open` egress, which
     * has no warden and no backstop by definition. The database is
     * attached to the routed network the sandbox is on, the self-test is
     * run, and the runner is asked to start.
     */
    public function test_the_runner_refuses_to_start_when_the_sandbox_can_reach_the_database(): void
    {
        $this->requireSandbox();

        $docker = new Docker;

        /*
         * 🛑 The compose database where there is one, and a stand-in where
         * there is not.
         *
         * CI runs this suite on the host with MySQL as a GitHub *service*
         * container, which carries no compose labels and is not ours to
         * re-attach. The mechanism under test is "a forbidden address that
         * turns out to be reachable fails the self-test and refuses
         * startup", and a listener on 3306 exercises it identically — so
         * the criterion is demonstrated in both places rather than skipped
         * in one of them. The build log says which ran where.
         */
        $database = $this->composeContainer($docker, 'db');
        $standIn = null;

        if ($database === null) {
            $standIn = 'docup-test-dataplane-'.bin2hex(random_bytes(6));

            $docker->capture([
                'run', '--detach', '--name', $standIn, '--network', 'bridge',
                '--label', 'docup.owner=build-runner',
                'busybox:stable', 'sh', '-c', 'while true; do echo x | nc -l -p 3306; done',
            ]);

            $database = $standIn;
        } else {
            [$status] = $docker->capture(['network', 'connect', 'bridge', $database]);

            if ($status !== 0) {
                $this->skipOrFailForImages('could not attach the database to the routed network');
            }
        }

        /*
         * The self-test resolves `db` through Docker's embedded resolver,
         * which only answers on a user-defined network — so on `bridge` the
         * forbidden target is named by address. Same check, same code path,
         * a name the sandbox can actually resolve.
         */
        [, $address] = $docker->capture([
            'inspect', '--format', '{{ with (index .NetworkSettings.Networks "bridge") }}{{ .IPAddress }}{{ end }}',
            $database,
        ]);

        config()->set('builds.sandbox.egress', 'open');
        config()->set('builds.sandbox.self_test.forbidden.database', trim($address).':3306');
        config()->set('builds.sandbox.isolation', 'runc');
        config()->set('docup.unsafe.acknowledge_unsandboxed', true);

        try {
            $result = (new IsolationSelfTest)->run();

            $this->assertFalse($result->passed, 'the self-test passed with MySQL reachable from the sandbox');
            $this->assertContains('database', $result->failures(), $result->summary);

            /*
             * 🛑 And the refusal reaches an init system. A self-test that
             * reported a failure while the runner carried on would leave an
             * installation accepting builds into a sandbox it had just
             * proven porous — §8.5.12 says "startup MUST fail", and a
             * non-zero exit is what that means to compose.
             */
            $exitCode = Artisan::call('docup:runner', ['--once' => true]);

            $this->assertSame(1, $exitCode, 'the runner started despite a failed §8.5.12 self-test');
            $this->assertStringContainsString('self-test FAILED', Artisan::output());
        } finally {
            if ($standIn === null) {
                $docker->capture(['network', 'disconnect', 'bridge', $database]);
            } else {
                $docker->capture(['rm', '--force', $standIn]);
            }

            config()->set('builds.sandbox.egress', 'allowlist');
            config()->set('builds.sandbox.self_test.forbidden.database', 'db:3306');
            config()->set('docup.unsafe.acknowledge_unsandboxed', false);

            /*
             * 🛑 Put the verdict back. The failed run above wrote `failed`
             * to the spool, and `BuildPipeline` refuses every build while
             * that is what it reads — so leaving it would turn one test
             * into a broken development stack. Re-run rather than fake:
             * writing `passed` without checking is the one thing this whole
             * file argues against.
             */
            $restored = (new IsolationSelfTest)->run();
            Spool::fromConfig()->writeSelfTest($restored->passed, $restored->summary);

            $this->assertTrue($restored->passed, 'the sandbox did not recover: '.$restored->summary);
        }
    }

    /**
     * 🛑 The case `internal: true` does **not** close.
     *
     * An internal Docker network has no route off the host — but it has a
     * route across itself, and two organisations' builds share it. Without
     * the warden's nftables ruleset one build can open a socket to
     * another's. This is the measurement ADR 0011 records, as a test.
     */
    public function test_a_build_cannot_reach_a_sibling_on_the_sandbox_network(): void
    {
        $this->requireSandbox();

        $docker = new Docker;
        $warden = new Warden;
        $network = (string) config('builds.sandbox.network');
        $sibling = 'docup-test-sibling-'.bin2hex(random_bytes(6));

        $docker->capture([
            'run', '--detach', '--name', $sibling, '--network', $network,
            '--label', 'docup.owner=build-runner',
            'busybox:stable', 'sh', '-c', 'while true; do echo SIBLING | nc -l -p 8080; done',
        ]);

        $wardenName = null;

        try {
            [, $address] = $docker->capture([
                'inspect', '--format',
                '{{ with (index .NetworkSettings.Networks "'.$network.'") }}{{ .IPAddress }}{{ end }}',
                $sibling,
            ]);

            $address = trim($address);
            $this->assertNotSame('', $address, 'the sibling did not join the sandbox network');

            $wardenName = $warden->start(bin2hex(random_bytes(16)), Stage::Build, $warden->proxyAddress());

            [, $output] = $docker->capture([
                'run', '--rm', '--network', 'container:'.$wardenName, '--cap-drop', 'ALL',
                '--label', 'docup.owner=build-runner',
                'busybox:stable', 'sh', '-c',
                '(echo x | timeout 4 nc '.$address.' 8080) >/dev/null 2>&1 && echo REACHED || echo BLOCKED',
            ]);

            $this->assertStringContainsString('BLOCKED', $output);
            $this->assertStringNotContainsString('REACHED', $output);

            // ...and the attempt is counted, which is what makes
            // `user.egress_blocked_at_layer3` a fact rather than a guess.
            $this->assertGreaterThan(0, $warden->blockedPackets($wardenName));
        } finally {
            if ($wardenName !== null) {
                $warden->stop($wardenName);
            }

            $docker->capture(['rm', '--force', $sibling]);
        }
    }

    /**
     * 🛑 And the build container cannot change the ruleset that constrains
     * it, which is the whole reason the warden is a separate container.
     */
    public function test_a_build_cannot_alter_the_backstop(): void
    {
        $this->requireSandbox();

        $docker = new Docker;
        $warden = new Warden;
        $wardenName = $warden->start(bin2hex(random_bytes(16)), Stage::Build, $warden->proxyAddress());

        try {
            [, $output] = $docker->capture([
                'run', '--rm', '--network', 'container:'.$wardenName, '--cap-drop', 'ALL',
                '--label', 'docup.owner=build-runner',
                'docup/warden:1', '--help',
            ]);

            $this->assertStringNotContainsString('ruleset installed', $output);
        } finally {
            $warden->stop($wardenName);
        }
    }

    private function composeContainer(Docker $docker, string $service): ?string
    {
        [$status, $output] = $docker->capture([
            'ps', '--quiet', '--filter', 'label=com.docker.compose.service='.$service,
        ]);

        $id = trim(explode("\n", trim($output))[0]);

        return $status === 0 && $id !== '' ? $id : null;
    }

    private function requireSandbox(): void
    {
        $this->requireBuildImages(['docup/warden:1']);

        if ((new Warden)->proxyAddress() === null) {
            $this->skipOrFailForImages('no egress proxy on the sandbox network; start the `proxy` service');
        }
    }
}
