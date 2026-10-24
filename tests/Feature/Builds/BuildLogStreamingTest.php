<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Builds\Log\BuildLog;
use App\Builds\Log\LogLine;
use App\Builds\Runner\DockerRunnerDriver;
use App\Builds\Runner\RunOutcome;
use App\Builds\Runner\Spool;
use App\Builds\RunSpecification;
use App\Builds\Sandbox\EgressMode;
use App\Builds\Stage;
use App\Credentials\SecretRedactor;
use App\Credentials\SecretRegistry;
use Tests\Support\RequiresBuildImages;
use Tests\TestCase;

/**
 * §8.5.21's streaming and §8.5.23's cancellation, against real containers.
 *
 * 🛑 **"Streams" is a claim about WHEN, and timestamps are how it is
 * proved.** Every other assertion about a log can be satisfied by a
 * runner that buffered everything and wrote it at the end — which is
 * exactly what Phase 06 did, and why a nine-minute build produced nothing
 * to read for nine minutes. Each record carries the millisecond it was
 * written, so a log whose first and last lines are seconds apart was
 * written progressively and one that was buffered is not.
 *
 * Runs in the `runner` container, which is the only one with a Docker
 * client (§8.5.13).
 */
final class BuildLogStreamingTest extends TestCase
{
    use RequiresBuildImages;

    private ?DockerRunnerDriver $driver = null;

    /** @var list<string> */
    private array $workspaces = [];

    private string $buildHex = '';

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('builds.log_spool', sys_get_temp_dir().'/docup-stream-'.bin2hex(random_bytes(6)));
        SecretRegistry::flush();
    }

    protected function tearDown(): void
    {
        foreach ($this->workspaces as $volume) {
            $this->driver?->destroyWorkspace($volume);
        }

        if ($this->buildHex !== '') {
            Spool::fromConfig()->discard($this->buildHex.'-build');
        }

        SecretRegistry::flush();

        parent::tearDown();
    }

    /**
     * 🛑 The exit criterion's mechanism: lines reach the log WHILE the
     * build runs.
     *
     * Eight seconds rather than nine minutes, because what is under test
     * is time-independent — the loop writes each line as it reads it —
     * and a nine-minute case in the suite would be nine minutes nobody
     * runs. The build log records which duration produced the evidence.
     */
    public function test_lines_are_written_while_the_container_is_still_running(): void
    {
        $outcome = $this->runScript('for i in 1 2 3 4 5 6 7 8; do echo "tick $i"; sleep 1; done');

        $this->assertSame(0, $outcome->exitCode, implode(' | ', array_slice($outcome->log, -3)));

        $lines = $this->liveLines();

        $this->assertGreaterThanOrEqual(8, count($lines));

        $elapsed = $lines[count($lines) - 1]->at - $lines[0]->at;

        $this->assertGreaterThan(
            5000,
            $elapsed,
            'every line carried nearly the same timestamp, so the log was buffered and written at the end',
        );
    }

    /**
     * 🛑 "...including values split across a chunk boundary."
     *
     * **The first attempt at this test was wrong in an instructive way.**
     * It printed one 64 KiB line with the secret at byte 65530 — and
     * §8.5.21's 8 KiB line truncation threw the secret away before any
     * boundary mattered. That is a safe outcome, but it tests nothing:
     * a secret beyond 8 KiB of one line can never reach a log.
     *
     * The case that is real is a stream of SHORT lines where a read
     * boundary happens to fall inside one of them. `fread` returns *up
     * to* 64 KiB and a pipe decides how much, so the boundary cannot be
     * aimed at — instead this prints a megabyte of output carrying the
     * secret two hundred times, which crosses a dozen boundaries, and
     * asserts that **every** occurrence arrived whole. One split would
     * show up as a missing occurrence and a fragment.
     */
    public function test_a_secret_crossing_read_boundaries_is_never_split_or_persisted(): void
    {
        $secret = 'ghp_'.str_repeat('m', 36);
        $occurrences = 200;

        $outcome = $this->runScript(
            'python3 -c "import sys'
            .'; pad = chr(102)*99'
            ."; secret = 'ghp_".str_repeat('m', 36)."'"
            .'; [sys.stdout.write((secret + pad[:40] if i % 25 == 24 else pad) + chr(10)) for i in range(5000)]"'
        );

        $this->assertSame(0, $outcome->exitCode, implode(' | ', array_slice($outcome->log, -3)));

        $raw = (string) file_get_contents($this->liveLogPath());

        $this->assertGreaterThan(400 * 1024, strlen($raw), 'not enough output to cross a read boundary');
        $this->assertSame(
            $occurrences,
            substr_count($raw, $secret),
            'a secret was split across a read boundary and reassembled as two fragments',
        );

        /*
         * 🛑 And now the boundary §8.5.21 actually names. The runner wrote
         * the raw lines — this stage was handed no credential, so nothing
         * on that side knew they were secret — and the worker redacts on
         * the way into the file an API serves.
         */
        SecretRegistry::remember($secret);
        $log = BuildLog::open($this->buildHex, new SecretRedactor);

        foreach ($this->liveLines() as $line) {
            $log->append($line->text, $line->stream);
        }

        $log->close();
        $persisted = (string) file_get_contents($log->path());

        $this->assertStringNotContainsString($secret, $persisted);
        $this->assertStringNotContainsString(substr($secret, 0, 20), $persisted);
        $this->assertStringContainsString(SecretRedactor::MARKER, $persisted);

        $log->delete();
    }

    /**
     * 🛑 §8.5.23: "cancelling a running build with effect within 5
     * seconds".
     *
     * The cancel arrives from another process two seconds in, which is
     * what makes this a cancellation rather than a refusal to start. The
     * budget covers the whole chain: the marker appearing, the runner's
     * half-second check noticing it, and `docker kill` returning.
     */
    public function test_a_running_container_is_cancelled_within_five_seconds(): void
    {
        $this->requireBuildImages(['docup/build-mkdocs:1']);

        $spool = Spool::fromConfig();
        $spool->ensure();

        $this->driver = new DockerRunnerDriver;
        $this->buildHex = bin2hex(random_bytes(16));
        $volume = $this->driver->createWorkspace($this->buildHex);
        $this->workspaces[] = $volume;

        $marker = $spool->cancelMarker($this->buildHex.'-build');

        // Another process, so the request genuinely arrives mid-run.
        $canceller = proc_open(
            ['sh', '-c', 'sleep 2; touch '.escapeshellarg($marker)],
            [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes,
        );

        $started = microtime(true);

        $outcome = $this->driver->run(new RunSpecification(
            buildId: $this->buildHex,
            stage: Stage::Build,
            imageKey: 'mkdocs',
            command: ['sh', '-c', 'echo running; sleep 300'],
            environment: [],
            volume: $volume,
            workdir: '/workspace',
            timeoutSeconds: 120,
            egress: EgressMode::None,
        ));

        $elapsed = microtime(true) - $started;

        if (is_resource($canceller)) {
            proc_close($canceller);
        }

        $this->assertSame(
            'cancelled.cancelled_by_request',
            $outcome->failureClass.'.'.$outcome->failureReason,
            'log tail: '.implode(' | ', array_slice($outcome->log, -3)),
        );

        $this->assertLessThan(
            5.0 + 2.0,
            $elapsed,
            '§8.5.23 gives cancellation five seconds; this took '.round($elapsed, 1).'s after a 2s delay',
        );
    }

    /**
     * 🛑 A cancelled build is not an OOM, and the order of the checks is
     * why.
     *
     * A container killed on request exits 137, which is also what the
     * kernel's OOM killer leaves behind — so a classifier that read the
     * resource signals first would tell an author their build ran out of
     * memory when somebody had pressed cancel.
     */
    public function test_cancellation_outranks_the_resource_signals(): void
    {
        $this->requireBuildImages(['docup/build-mkdocs:1']);

        $spool = Spool::fromConfig();
        $spool->ensure();

        $this->driver = new DockerRunnerDriver;
        $this->buildHex = bin2hex(random_bytes(16));
        $volume = $this->driver->createWorkspace($this->buildHex);
        $this->workspaces[] = $volume;

        $spool->requestCancel($this->buildHex.'-build');

        $outcome = $this->driver->run(new RunSpecification(
            buildId: $this->buildHex,
            stage: Stage::Build,
            imageKey: 'mkdocs',
            command: ['sh', '-c', 'sleep 60'],
            environment: [],
            volume: $volume,
            workdir: '/workspace',
            timeoutSeconds: 120,
            egress: EgressMode::None,
        ));

        $this->assertSame('cancelled', $outcome->failureClass);
        $this->assertNotSame('resource', $outcome->failureClass);
    }

    /** @return list<LogLine> */
    private function liveLines(): array
    {
        $lines = [];

        foreach (file($this->liveLogPath()) ?: [] as $raw) {
            $line = LogLine::decode($raw);

            if ($line instanceof LogLine) {
                $lines[] = $line;
            }
        }

        return $lines;
    }

    private function liveLogPath(): string
    {
        return Spool::fromConfig()->liveLog($this->buildHex.'-build');
    }

    private function runScript(string $script): RunOutcome
    {
        $this->requireBuildImages(['docup/build-mkdocs:1']);

        $this->driver = new DockerRunnerDriver;
        $this->buildHex = bin2hex(random_bytes(16));

        try {
            $volume = $this->driver->createWorkspace($this->buildHex);
        } catch (\RuntimeException $unavailable) {
            $this->skipOrFailForImages('no container runtime: '.$unavailable->getMessage());
        }

        $this->workspaces[] = $volume;

        return $this->driver->run(new RunSpecification(
            buildId: $this->buildHex,
            stage: Stage::Build,
            imageKey: 'mkdocs',
            command: ['sh', '-c', $script],
            environment: [],
            volume: $volume,
            workdir: '/workspace',
            timeoutSeconds: 120,
            egress: EgressMode::None,
        ));
    }
}
