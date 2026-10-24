<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Builds\Runner\DockerRunnerDriver;
use App\Builds\Runner\RunOutcome;
use App\Builds\RunSpecification;
use App\Builds\Sandbox\EgressMode;
use App\Builds\Stage;
use Tests\Support\RequiresBuildImages;
use Tests\TestCase;

/**
 * §8.5.21's log caps, against a container that is actually trying to exceed
 * them.
 *
 * > "The system MUST stream build logs line by line, strip NUL bytes,
 * > truncate lines over 8 KiB, cap the log at 10 MiB (head 2 MiB + tail
 * > 8 MiB with a marker)"
 *
 * 🛑 Enforced **while reading**, in the runner, not after the bytes have
 * crossed the spool. A cap applied afterwards is a cap on what is stored,
 * not on what the output costs — and the process being protected is the one
 * reading an unbounded stream from a container that may be trying to exhaust
 * it. Measured here by asking a container to produce more than the cap and
 * checking what comes back.
 *
 * Runs in the `runner` container, where the Docker client lives (§8.5.13).
 */
final class RunnerLogCapsTest extends TestCase
{
    use RequiresBuildImages;

    private ?DockerRunnerDriver $driver = null;

    private ?string $volume = null;

    protected function tearDown(): void
    {
        if ($this->driver !== null && $this->volume !== null) {
            $this->driver->destroyWorkspace($this->volume);
        }

        parent::tearDown();
    }

    public function test_a_long_line_is_truncated_and_nul_bytes_are_stripped(): void
    {
        $outcome = $this->runScript(implode('; ', [
            // 64 KiB on one line, against §8.5.21's 8 KiB line ceiling.
            'python3 -c "print(\'A\' * 65536)"',
            // A NUL in the middle of an otherwise ordinary line.
            'printf "before\\000after\\n"',
            'echo TAIL-MARKER',
        ]));

        $this->assertSame(0, $outcome->exitCode, implode(' | ', array_slice($outcome->log, 0, 3)));

        $longest = 0;

        foreach ($outcome->log as $line) {
            $longest = max($longest, strlen($line));
            $this->assertStringNotContainsString("\0", $line, 'a NUL byte survived into the log');
        }

        $this->assertGreaterThan(8192, $longest, 'the truncation marker is appended to the 8 KiB prefix');
        $this->assertLessThan(8400, $longest, 'a line over 8 KiB was not truncated (§8.5.21)');

        $joined = implode("\n", $outcome->log);

        $this->assertStringContainsString('line truncated at 8 KiB', $joined);
        $this->assertStringContainsString('beforeafter', $joined, 'the line survived; only the NUL was removed');
        $this->assertStringContainsString('TAIL-MARKER', $joined, 'the stream continued after the long line');
    }

    /**
     * 🛑 The 10 MiB total, with the container still exiting cleanly.
     *
     * The cap must not become a kill: a build whose generator is merely
     * chatty has not failed, and turning verbosity into a build failure
     * would be a worse outcome than a truncated log.
     */
    public function test_an_oversized_log_is_capped_without_failing_the_build(): void
    {
        /*
         * ~12 MiB in 60-byte lines: comfortably past the cap, and small
         * enough per line that the 8 KiB rule is not what trips.
         *
         * `yes | head` rather than a one-liner in an interpreter. The whole
         * script is a single argv element, so it cannot contain a newline
         * (§8.5.13) — and an inline Python one-liner written with `\n` in a
         * PHP string is how that constraint gets discovered the hard way,
         * as it was here.
         */
        $outcome = $this->runScript(
            'yes '.str_repeat('x', 60).' | head -n 200000; echo AFTER-THE-FLOOD'
        );

        $bytes = strlen(implode("\n", $outcome->log));

        $this->assertLessThan(11 * 1024 * 1024, $bytes, 'the log exceeded §8.5.21s 10 MiB cap');
        $this->assertStringContainsString('log capped at', implode("\n", array_slice($outcome->log, -3)));

        // Capped, not killed.
        $this->assertSame(0, $outcome->exitCode);
        $this->assertNull($outcome->failureClass);
    }

    /**
     * 🛑 A container that writes a lot and exits at once keeps all of it.
     *
     * The regression this guards was found by the test above and is worth
     * its own case, because the two fail in different ways. The read loop
     * used to stop the instant `proc_get_status` reported the process
     * gone, discarding whatever the kernel still held in the pipes — so a
     * fast container lost everything after its first chunk. The visible
     * symptom was §8.5.21's truncation appearing not to work; the actual
     * fault was output never read.
     *
     * "Exits immediately" is the case that matters: a long-running build
     * gives the loop many passes and hides this completely, which is why
     * it survived a phase.
     */
    public function test_output_from_a_container_that_exits_immediately_is_not_lost(): void
    {
        $outcome = $this->runScript(
            'python3 -c "print(chr(65) * 65536)"; echo FINAL-LINE'
        );

        $joined = implode('
', $outcome->log);

        $this->assertStringContainsString('FINAL-LINE', $joined, 'the tail of a fast container was dropped');
        $this->assertStringContainsString('line truncated at 8 KiB', $joined);
        $this->assertSame(0, $outcome->exitCode);
    }

    /** Named `runScript` because `run()` is final on PHPUnit's TestCase. */
    private function runScript(string $script): RunOutcome
    {
        $this->requireBuildImages(['docup/build-mkdocs:1']);

        $this->driver = new DockerRunnerDriver;
        $buildId = bin2hex(random_bytes(16));

        try {
            $this->volume = $this->driver->createWorkspace($buildId);
        } catch (\RuntimeException $unavailable) {
            $this->skipOrFailForImages('no container runtime: '.$unavailable->getMessage());
        }

        return $this->driver->run(new RunSpecification(
            buildId: $buildId,
            stage: Stage::Build,
            imageKey: 'mkdocs',
            command: ['sh', '-c', $script],
            environment: [],
            volume: (string) $this->volume,
            workdir: '/workspace',
            timeoutSeconds: 300,
            egress: EgressMode::None,
        ));
    }
}
