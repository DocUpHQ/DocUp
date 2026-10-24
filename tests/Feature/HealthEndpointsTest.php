<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature;

use App\Builds\Runner\Spool;
use Tests\TestCase;

/**
 * §8.1.10's three health endpoints.
 *
 * 🛑 **These exist because the compose healthcheck had been failing since
 * Phase 01 and nothing noticed.** `bootstrap/app.php` passes
 * `health: '/up'` to `withRouting()`, and that parameter is silently
 * ignored when `using:` is supplied — which it is, for the route-ordering
 * reason recorded there. So `/up` 404'd, `curl -fsS` returned non-zero
 * every ten seconds, and `docup-app-1` reported **unhealthy** for six
 * phases.
 *
 * Phase 01's build log drew exactly the right conclusion from the same
 * defect on the worker container — "a configuration comment cannot fail a
 * build; assert the outcome" — and the application container had it the
 * whole time. This file is that lesson applied: the endpoints are asserted
 * by request, not by reading the routing configuration.
 */
final class HealthEndpointsTest extends TestCase
{
    /** Liveness answers without touching anything. */
    public function test_liveness_is_200_and_uncacheable(): void
    {
        $response = $this->get('/_/health');

        $response->assertOk();
        $response->assertJson(['status' => 'ok']);
        $response->assertHeader('Cache-Control', 'no-store, private');
    }

    /** 🛑 The regression guard: the old path must stay gone, or nobody fixes it twice. */
    public function test_the_old_up_path_is_not_what_the_healthcheck_uses(): void
    {
        $this->assertStringContainsString(
            '/_/health',
            (string) file_get_contents(base_path('compose.yaml')),
            'the compose healthcheck must point at the endpoint that exists',
        );

        $this->assertStringNotContainsString(
            'http://localhost/up',
            (string) file_get_contents(base_path('compose.yaml')),
        );
    }

    /** Readiness reports each dependency separately. */
    public function test_readiness_reports_its_dependencies(): void
    {
        $response = $this->get('/_/health/ready');

        $response->assertOk();
        $response->assertJsonStructure(['status', 'checks' => ['database', 'cache']]);
        $response->assertJson(['status' => 'ready']);
    }

    /**
     * 🛑 The self-test endpoint reports `never_run` rather than passing
     * when no runner has written a verdict.
     *
     * An endpoint that said "ok" because it had nothing to report would be
     * worse than one that said nothing at all: §8.5.12 exists to make the
     * absence of a check visible.
     */
    public function test_the_self_test_endpoint_is_503_when_no_verdict_exists(): void
    {
        config()->set('builds.enabled', true);
        config()->set('builds.spool', sys_get_temp_dir().'/docup-health-'.bin2hex(random_bytes(6)));
        $this->app->forgetInstance(Spool::class);

        $response = $this->get('/_/health/self-test');

        $response->assertStatus(503);
        $response->assertJson(['sandbox_isolation' => 'never_run']);
    }

    /** ...and `not_applicable` in hosting-only mode, which is a 200. */
    public function test_the_self_test_endpoint_is_200_in_hosting_only_mode(): void
    {
        config()->set('builds.enabled', false);
        config()->set('builds.spool', sys_get_temp_dir().'/docup-health-'.bin2hex(random_bytes(6)));
        $this->app->forgetInstance(Spool::class);

        $response = $this->get('/_/health/self-test');

        $response->assertOk();
        $response->assertJson(['sandbox_isolation' => 'not_applicable', 'builds_enabled' => false]);
    }

    /**
     * 🛑 None of the three leaks anything.
     *
     * They are unauthenticated by design — an orchestrator has no session —
     * so the response must contain nothing a reader could not already
     * infer by making a request.
     */
    public function test_no_health_endpoint_discloses_a_hostname_or_a_credential(): void
    {
        config()->set('builds.enabled', true);

        foreach (['/_/health', '/_/health/ready', '/_/health/self-test'] as $path) {
            $body = $this->get($path)->getContent();

            $this->assertIsString($body);

            foreach ([(string) config('database.connections.mysql.password'), (string) config('app.key')] as $secret) {
                if ($secret !== '') {
                    $this->assertStringNotContainsString($secret, $body, $path.' leaked a credential');
                }
            }

            $this->assertStringNotContainsString('mysql:host', $body);
        }
    }
}
