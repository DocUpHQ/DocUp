<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Builds\FailureCatalogue;
use App\Builds\Runner\DockerRunnerDriver;
use App\Builds\Runner\RunOutcome;
use App\Builds\Runner\Spool;
use App\Builds\Runner\Warden;
use App\Builds\Runner\Workspace;
use App\Builds\RunSpecification;
use App\Builds\Sandbox\EgressMode;
use App\Builds\Stage;
use Tests\Support\RequiresBuildImages;
use Tests\TestCase;

/**
 * 🛑 Phase 07's exit criteria, one hostile build at a time.
 *
 * > "A fork bomb, a 10 GB writer, a non-allowlisted apt package, an
 * > outbound `curl` to a blocked host, a `conf.py` that curls the cloud
 * > metadata endpoint at `169.254.169.254`, an attempted runtime-socket
 * > mount and a 20-minute sleep each reach a **distinct** terminal state
 * > with a specific user-facing message and a stable failure identifier."
 *
 * 🛑 **"Distinct" is the requirement that does the work**, and it is
 * asserted directly at the end of this file rather than inferred from seven
 * passing cases. A sandbox that refused all seven with one generic
 * `build_failed` would satisfy a careless reading of every other assertion
 * here while telling an author nothing about which control fired — and
 * telling an operator nothing about whether a build was badly written or
 * trying to reach the cloud metadata endpoint.
 *
 * Each case also asserts that the identifier has a **specific** message in
 * {@see FailureCatalogue}: the fallback sentence is itself detectable, so
 * "has a message" cannot be satisfied by forgetting to write one.
 *
 * Runs in the `runner` container, which is the only one with a Docker
 * client (§8.5.13). It needs the sandbox network, the egress proxy and the
 * warden image as well as the build images, so `DOCUP_E2E=1` is what turns
 * a skip here into a failure.
 */
final class SandboxRefusalsTest extends TestCase
{
    use RequiresBuildImages;

    private ?DockerRunnerDriver $driver = null;

    /** @var list<string> */
    private array $workspaces = [];

    protected function tearDown(): void
    {
        foreach ($this->workspaces as $volume) {
            $this->driver?->destroyWorkspace($volume);
        }

        parent::tearDown();
    }

    /** §8.5.18's PID ceiling, and the evidence only the cgroup carries. */
    public function test_a_fork_bomb_exhausts_the_pid_ceiling(): void
    {
        $outcome = $this->runInSandbox(
            'bomb() { bomb & bomb & }; bomb 2>/dev/null; sleep 2; echo survived',
            egress: EgressMode::None,
        );

        $this->assertIdentifier('resource.pid_limit_exceeded', $outcome);

        /*
         * 🛑 The part worth stating: the shell very often exits **0**. The
         * kernel refused the forks, the build "succeeded", and without the
         * cgroup counter DocUp would have published whatever half-built
         * site the surviving processes managed to produce.
         */
        $this->assertGreaterThan(
            0,
            $outcome->facts['resources']['pid_limit_hits'] ?? 0,
            'pids.events:max did not register; is /hostcg mounted into the runner?',
        );
    }

    /** §8.5.18's disk limit, enforced while the build runs. */
    public function test_a_large_writer_exhausts_the_workspace(): void
    {
        /*
         * 64 MiB rather than the shipped 2 GiB, so the kill lands on the
         * first poll instead of after a gigabyte of real disk. The fixture
         * still asks for 10 GB — what is under test is that the ceiling
         * bites, not how large it is.
         */
        config()->set('builds.limits.disk_mb', 64);

        $outcome = $this->runInSandbox(
            'dd if=/dev/zero of=/workspace/big bs=1M count=10240 2>/dev/null; echo wrote',
            egress: EgressMode::None,
            timeout: 120,
        );

        $this->assertIdentifier('resource.disk_quota_exceeded', $outcome);
    }

    /**
     * §8.5.9, in the stage where dependencies are installed.
     *
     * The allowlist carries package *indexes* and git hosts. A distribution
     * package manager is deliberately absent, because §8.5.14 pre-bakes the
     * images — so a build reaching for `deb.debian.org` is a build doing
     * something the image was supposed to have done already.
     */
    public function test_a_non_allowlisted_package_host_is_refused_during_environment(): void
    {
        $outcome = $this->runInSandbox(
            $this->fetchWith('https://deb.debian.org/debian/dists/stable/Release'),
            stage: Stage::Environment,
        );

        $this->assertIdentifier('user.package_host_not_allowlisted', $outcome);
    }

    /** §8.5.9, from the generator itself. */
    public function test_an_outbound_request_to_a_blocked_host_is_refused(): void
    {
        $outcome = $this->runInSandbox($this->fetchWith('https://example.com/'));

        $this->assertIdentifier('user.egress_host_not_allowlisted', $outcome);
    }

    /**
     * 🛑 The cloud metadata endpoint gets its own identifier.
     *
     * Not because the mechanism differs — the same proxy refuses it — but
     * because the sentence an author reads must. An unreachable package
     * index is a packaging problem; a build reaching for the host's own
     * cloud credentials is an incident, and §14's threat model treats it as
     * one.
     */
    public function test_a_build_reaching_the_cloud_metadata_endpoint_is_refused(): void
    {
        $outcome = $this->runInSandbox(
            $this->fetchWith('http://169.254.169.254/latest/meta-data/'),
        );

        $this->assertIdentifier('user.egress_metadata_endpoint_denied', $outcome);
    }

    /**
     * 🛑 §8.5.13, at the one boundary where a document meets the runtime.
     *
     * The runner reads a specification off a shared volume. If that
     * document could carry a `mounts` key that the argv template later
     * learned to honour, the socket would be one refactor away from a build
     * container — so a document carrying one is refused **now**, by the
     * constructor, with an identifier that says what was asked for.
     */
    public function test_a_spool_document_requesting_the_runtime_socket_is_refused(): void
    {
        $spool = Spool::fromConfig();
        $spool->ensure();

        $hostile = [
            'build_id' => str_repeat('b', 32),
            'stage' => 'build',
            'image_key' => 'mkdocs',
            'command' => ['echo', 'hello'],
            'environment' => [],
            'volume' => 'docup-build-'.str_repeat('b', 32),
            'workdir' => '/workspace',
            'timeout_seconds' => 30,
            'egress' => 'none',
            'mounts' => ['/var/run/docker.sock:/var/run/docker.sock'],
        ];

        $jobId = str_repeat('b', 32).'-build';
        file_put_contents($spool->inbox($jobId), json_encode($hostile, JSON_THROW_ON_ERROR));

        try {
            $this->assertNull($spool->claimNext(), 'a privilege-seeking document must not become a job');

            $result = $spool->readResult($jobId);

            $this->assertInstanceOf(RunOutcome::class, $result);
            $this->assertSame('rejected.runtime_socket_requested', $result->failureClass.'.'.$result->failureReason);
            $this->assertNotSame(
                FailureCatalogue::message('does.not.exist'),
                FailureCatalogue::message('rejected.runtime_socket_requested'),
            );
        } finally {
            $spool->discard($jobId);
        }
    }

    /** 🛑 And the socket is not in the sandbox either, document or no document. */
    public function test_the_runtime_socket_is_not_present_inside_a_build_container(): void
    {
        $outcome = $this->runInSandbox(
            'test -e /var/run/docker.sock && echo SOCKET-PRESENT || echo no-socket',
            egress: EgressMode::None,
        );

        $this->assertStringContainsString('no-socket', implode("\n", $outcome->log));
        $this->assertStringNotContainsString('SOCKET-PRESENT', implode("\n", $outcome->log));
    }

    /** §8.5.18's wall clock, with the stage's own timeout standing in for it. */
    public function test_a_long_sleep_hits_the_stage_timeout(): void
    {
        $outcome = $this->runInSandbox(
            'sleep 1200',
            egress: EgressMode::None,
            // 1200 seconds is the fixture; five is this suite's patience.
            // What is under test is that the clock stops the build, not how
            // long the clock is.
            timeout: 5,
        );

        $this->assertIdentifier('timeout.stage_timeout', $outcome);
    }

    /**
     * 🛑 The requirement the other seven cannot each assert for themselves.
     *
     * Seven refusals that all produced `user.build_command_failed` would
     * pass every individual assertion above if each were written loosely.
     * This asserts the set.
     */
    public function test_every_exit_criterion_has_a_distinct_identifier_and_its_own_message(): void
    {
        $identifiers = [
            'resource.pid_limit_exceeded',
            'resource.disk_quota_exceeded',
            'user.package_host_not_allowlisted',
            'user.egress_host_not_allowlisted',
            'user.egress_metadata_endpoint_denied',
            'rejected.runtime_socket_requested',
            'timeout.stage_timeout',
        ];

        $this->assertCount(count($identifiers), array_unique($identifiers));

        $messages = [];

        foreach ($identifiers as $identifier) {
            $message = FailureCatalogue::message($identifier);

            $this->assertTrue(
                FailureCatalogue::has($identifier),
                $identifier.' has no entry in the failure catalogue',
            );

            $this->assertStringNotContainsString(
                'No description is recorded',
                $message,
                $identifier.' fell back to the catalogue default',
            );

            $messages[] = $message;
        }

        $this->assertCount(
            count($identifiers),
            array_unique($messages),
            'two exit criteria share a user-facing message, so an author cannot tell them apart',
        );
    }

    /**
     * A python one-liner that honours the proxy environment.
     *
     * `urllib` reads `http_proxy`/`https_proxy`, which is exactly what a
     * real dependency installer does — so this exercises the same path a
     * `pip install` would rather than a hand-rolled socket.
     */
    private function fetchWith(string $url): string
    {
        return 'python3 -c '
            .escapeshellarg('import urllib.request;urllib.request.urlopen("'.$url.'", timeout=20).read()');
    }

    private function assertIdentifier(string $expected, RunOutcome $outcome): void
    {
        $actual = $outcome->failureClass === null
            ? 'succeeded'
            : $outcome->failureClass.'.'.$outcome->failureReason;

        $this->assertSame(
            $expected,
            $actual,
            'log tail: '.implode(' | ', array_slice($outcome->log, -4)),
        );

        $this->assertStringNotContainsString(
            'No description is recorded',
            FailureCatalogue::message($expected),
            $expected.' has no user-facing message',
        );
    }

    private function runInSandbox(
        string $script,
        Stage $stage = Stage::Build,
        EgressMode $egress = EgressMode::Allowlist,
        int $timeout = 90,
    ): RunOutcome {
        $this->requireBuildImages(['docup/build-mkdocs:1', 'docup/warden:1']);
        $this->requireSandboxNetwork();

        $this->driver = new DockerRunnerDriver;
        $buildId = bin2hex(random_bytes(16));
        $volume = $this->driver->createWorkspace($buildId);
        $this->workspaces[] = $volume;

        return $this->driver->run(new RunSpecification(
            buildId: $buildId,
            stage: $stage,
            imageKey: 'mkdocs',
            command: ['sh', '-c', $script],
            environment: [],
            volume: $volume,
            workdir: '/workspace',
            timeoutSeconds: $timeout,
            egress: $egress,
        ));
    }

    /**
     * 🛑 Without the proxy there is no allowlist to refuse anything, and
     * three of these cases would pass for the wrong reason — a build with
     * no egress at all fails every outbound request too. Checked, so the
     * absence is a skip rather than a false green.
     */
    private function requireSandboxNetwork(): void
    {
        if (! Workspace::rootIsVisible()) {
            $this->skipOrFailForImages('no workspace root; start the `runner` service from compose.yaml');
        }

        if ((new Warden)->proxyAddress() === null) {
            $this->skipOrFailForImages('no egress proxy on the sandbox network; start the `proxy` service');
        }
    }
}
