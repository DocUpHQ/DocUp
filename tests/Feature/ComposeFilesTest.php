<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature;

use Tests\TestCase;

/**
 * 🛑 SPEC 8.1.3: MailPit and phpMyAdmin are absent from the production compose
 * file AS IMAGES, not merely disabled by a profile.
 *
 * The reasoning is in the requirement: a profile can be flipped by an operator
 * in a hurry, and a missing service cannot. This test asserts both halves -
 * absent from production, present in development - because a test that only
 * checked absence would pass just as happily if someone deleted them from both
 * and quietly broke the development experience instead.
 */
final class ComposeFilesTest extends TestCase
{
    private function compose(string $file): string
    {
        $path = base_path($file);

        $this->assertFileExists($path, "{$file} is a Phase 01 deliverable");

        return (string) file_get_contents($path);
    }

    public function test_the_production_compose_file_contains_no_development_images(): void
    {
        $production = $this->compose('compose.yaml');

        // Assert against STRUCTURE, not prose: compose.yaml carries a comment
        // explaining this very requirement, and a whole-file grep would fail on
        // its own documentation.
        foreach (['mailpit', 'phpmyadmin', 'adminer'] as $forbidden) {
            $this->assertDoesNotMatchRegularExpression(
                '/^\s{2}'.preg_quote($forbidden, '/').'\s*:/mi',
                $production,
                "compose.yaml declares a [{$forbidden}] service (SPEC 8.1.3): a profile can be "
                .'flipped, a missing service cannot.',
            );

            $this->assertDoesNotMatchRegularExpression(
                '/^\s*image:\s*\S*'.preg_quote($forbidden, '/').'/mi',
                $production,
                "compose.yaml references a [{$forbidden}] image (SPEC 8.1.3)",
            );
        }
    }

    public function test_the_development_overlay_provides_them_on_loopback_only(): void
    {
        $dev = $this->compose('compose.dev.yaml');

        $this->assertStringContainsString('mailpit', $dev);
        $this->assertStringContainsString('phpmyadmin', $dev);

        // SPEC 8.1.2: bound to 127.0.0.1, never 0.0.0.0. A development mail
        // catcher reachable from the network is an open relay and a mailbox.
        foreach (['127.0.0.1:1025:1025', '127.0.0.1:8025:8025', '127.0.0.1:8081:80'] as $binding) {
            $this->assertStringContainsString(
                $binding,
                $dev,
                "development services must bind to loopback only; expected [{$binding}]",
            );
        }
    }

    public function test_the_production_stack_is_the_five_services_the_spec_names(): void
    {
        $production = $this->compose('compose.yaml');

        // SPEC 8.1.1: application, MySQL, Valkey, a queue worker and the egress
        // proxy, with no external service account required.
        //
        // 🛑 `worker` and `runner` are both here from Phase 06, and they are
        // different things: `worker` is the queue worker in SPEC 11.2's app
        // zone, holding the database credentials; `runner` is the sandbox
        // broker in the runner zone, holding the container-runtime socket
        // and no credentials at all. Phase 01 had one service called
        // `runner` doing the first job, which is why the rename happened.
        //
        // 🛑 `scheduler` is here from Phase 11, and it is asserted rather
        // than merely present because its ABSENCE is what went unnoticed
        // for four phases. routes/console.php has scheduled SPEC 8.22.1's
        // daily signed audit anchor and SPEC 8.22.6's mandatory hard purge
        // since Phase 02, and nothing ran `schedule:work`, so neither had
        // ever executed in a deployment. A scheduler that is absent looks
        // exactly like one with nothing due, which is why the only thing
        // that can catch it is a test naming it.
        foreach (['app:', 'db:', 'cache:', 'worker:', 'runner:', 'scheduler:'] as $service) {
            $this->assertStringContainsString($service, $production);
        }

        $this->assertStringContainsString(
            'schedule:work',
            $production,
            '🛑 the scheduler service must actually run the scheduler; a container that boots and waits is the bug this caught',
        );

        $this->assertStringContainsString('mysql:8.4', $production, 'SPEC 11.1: MySQL 8.4 LTS; 8.0 is EOL');
        $this->assertStringContainsString('valkey', $production, 'SPEC 11.1: Valkey, not Redis');
    }

    /**
     * SPEC 8.5.13: the runner is a separate service from the application
     * because it is the sole holder of the container-runtime socket, and no
     * request-handling process may hold one. Separate since Phase 01, so the
     * boundary was never retrofitted — Phase 06 only had to fill it in.
     *
     * `RunnerIsolationTest` asserts what each side may hold; this asserts
     * only that the two are distinct.
     */
    public function test_the_runner_is_a_separate_service_from_the_application(): void
    {
        $production = $this->compose('compose.yaml');

        $appAt = strpos($production, "\n  app:");
        $runnerAt = strpos($production, "\n  runner:");

        $this->assertNotFalse($appAt);
        $this->assertNotFalse($runnerAt);
        $this->assertNotSame($appAt, $runnerAt, 'app and runner must be distinct services');
    }

    /**
     * 🛑 The runner must declare its own healthcheck.
     *
     * The FrankenPHP base image ships a HEALTHCHECK that curls Caddy's admin
     * API on port 2019. The runner is a queue worker and serves no HTTP, so
     * inheriting it leaves the container permanently unhealthy - which is the
     * state it was actually found in during Phase 01.
     *
     * That matters beyond tidiness: anything gated on
     * `condition: service_healthy` for the runner would wait for ever, and
     * once a container is permanently unhealthy a genuine failure looks
     * exactly like the standing one. Asserted here because the symptom is
     * invisible unless somebody happens to read `docker compose ps`.
     */
    public function test_the_runner_overrides_the_inherited_http_healthcheck(): void
    {
        $production = $this->compose('compose.yaml');

        $runnerAt = strpos($production, "\n  runner:");
        $this->assertNotFalse($runnerAt);

        // The runner block runs to the start of the top-level volumes key.
        $volumesAt = strpos($production, "\nvolumes:", $runnerAt);
        $runner = substr(
            $production,
            $runnerAt,
            ($volumesAt === false ? strlen($production) : $volumesAt) - $runnerAt,
        );

        $this->assertStringContainsString(
            'healthcheck:',
            $runner,
            'the runner inherits the base image HTTP healthcheck unless it declares its own',
        );

        // Comments stripped before the negative assertion, for the third time
        // in this codebase: ArchitectureTest::code() does the same for PHP
        // because two of its tests failed on their own documentation. The
        // comment beside this healthcheck explains what port 2019 is, and a
        // plain search would therefore match the explanation of the rule
        // rather than a violation of it.
        $this->assertStringNotContainsString(
            '2019',
            $this->withoutComments($runner),
            'port 2019 is Caddy\'s admin API; the runner serves no HTTP',
        );
    }

    /**
     * Strip whole-line YAML comments.
     *
     * Whole-line only, deliberately: an inline `#` can legitimately appear
     * inside a quoted scalar such as a password, and a parser clever enough to
     * tell the two apart is a parser that can be wrong. Assertions that need
     * this helper should be written against whole-line comments.
     */
    private function withoutComments(string $yaml): string
    {
        $kept = array_filter(
            preg_split('/\R/', $yaml) ?: [],
            static fn (string $line): bool => ! str_starts_with(ltrim($line), '#'),
        );

        return implode("\n", $kept);
    }
}
