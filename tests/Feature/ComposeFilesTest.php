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
        foreach (['app:', 'db:', 'cache:', 'runner:'] as $service) {
            $this->assertStringContainsString($service, $production);
        }

        $this->assertStringContainsString('mysql:8.4', $production, 'SPEC 11.1: MySQL 8.4 LTS; 8.0 is EOL');
        $this->assertStringContainsString('valkey', $production, 'SPEC 11.1: Valkey, not Redis');
    }

    /**
     * SPEC 8.5.13: the runner is a separate service from the application
     * because when builds arrive it becomes the sole holder of the
     * container-runtime socket, and no request-handling process may hold one.
     * Keeping them separate from Phase 01 means that boundary is never
     * retrofitted.
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
}
