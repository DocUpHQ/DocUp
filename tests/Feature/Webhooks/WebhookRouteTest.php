<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Webhooks;

use App\Http\Controllers\WebhookController;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Support\Facades\Route;
use Tests\TestCase;

/**
 * 🛑 Phase 11's negative exit criterion: "The unsigned generic endpoint
 * **does not exist** — asserted by a route test."
 *
 * > §8.19.3: "An **unsigned** generic webhook endpoint MUST NOT exist —
 * > Read the Docs ships one and it is a build-trigger oracle."
 *
 * An absence cannot be proved by testing the endpoints that do exist, which
 * is why this walks the route table instead. Every test in
 * {@see WebhookDeliveryTest} would still pass on the day somebody adds a
 * second, unauthenticated route beside the first — and that route is
 * exactly what an attacker would look for.
 */
final class WebhookRouteTest extends TestCase
{
    /**
     * 🛑 There is exactly ONE route into {@see WebhookController}.
     *
     * Not "at least one", and not "one per provider": a per-provider route
     * set is how an unsigned one gets added for "the simple case", and
     * nothing in the diff would look wrong.
     */
    public function test_exactly_one_route_reaches_the_webhook_controller(): void
    {
        $routes = $this->webhookRoutes();

        $this->assertCount(
            1,
            $routes,
            '§8.19.3: one signed endpoint, and adding a second is the thing this test exists to catch',
        );

        $route = $routes[0];

        $this->assertSame('_/webhook/{integration}', $route->uri());
        $this->assertSame(['POST'], array_values(array_diff($route->methods(), ['HEAD'])));
    }

    /**
     * 🛑 The one route takes an integration id, so there is no path that
     * reaches the controller without naming the credential to verify
     * against.
     *
     * A route of `_/webhook/{provider}` or a bare `_/webhook` would be the
     * unsigned generic endpoint by construction: with nothing to look the
     * secret up by, the only thing the handler could do is trust the body.
     */
    public function test_the_route_requires_an_integration_identifier(): void
    {
        $route = $this->webhookRoutes()[0];

        $this->assertContains('integration', $route->parameterNames());

        /*
         * 🛑 Asserted by behaviour rather than by the literal pattern,
         * because the pattern is Laravel's and changes between releases —
         * a test pinned to its spelling would fail on an upgrade without
         * anything being wrong, and would be "fixed" by pasting in the new
         * spelling without anyone checking it still constrains.
         */
        $constraint = $route->wheres['integration'] ?? '';

        $this->assertNotSame('', $constraint, 'the id must be constrained at the router');

        $this->assertSame(
            1,
            preg_match('#^'.$constraint.'$#', '0193a4b1-0000-7000-8000-000000000000'),
            'a UUID must match',
        );

        $this->assertSame(
            0,
            preg_match('#^'.$constraint.'$#', '../../etc/passwd'),
            'anything that is not a UUID 404s at the router rather than reaching the ingestor',
        );
    }

    /**
     * 🛑 No route anywhere in the application has "webhook" in its path
     * except that one.
     *
     * Catches the second-endpoint case even when it is wired to a
     * different controller — a closure in a service provider, a route in a
     * package, the "quick trigger for CI" somebody adds in a hurry.
     */
    public function test_no_other_route_accepts_a_webhook_shaped_path(): void
    {
        $paths = [];

        foreach (Route::getRoutes()->getRoutes() as $route) {
            if (str_contains(strtolower($route->uri()), 'webhook')
                || str_contains(strtolower($route->uri()), 'hook/')) {
                $paths[] = $route->uri();
            }
        }

        $this->assertSame(
            ['_/webhook/{integration}'],
            array_values(array_unique($paths)),
            '§8.19.3 forbids an unsigned generic endpoint; this is how a second one would be found',
        );
    }

    /**
     * 🛑 The route is NOT in the `web` group.
     *
     * Two reasons, and they pull in opposite directions, which is why this
     * is asserted rather than left to a comment:
     *
     *   - `web` validates a CSRF token, which a provider cannot obtain, so
     *     every genuine delivery would answer 419.
     *   - `web` also starts a session and resolves a tenant, which an
     *     unauthenticated endpoint must not do before it has verified
     *     anything.
     */
    public function test_the_route_is_outside_the_web_middleware_group(): void
    {
        $middleware = $this->webhookRoutes()[0]->gatherMiddleware();

        $this->assertNotContains('web', $middleware);

        foreach ($middleware as $entry) {
            $this->assertStringNotContainsString(
                'ValidateCsrfToken',
                (string) $entry,
                'a provider has no session, so CSRF validation would refuse every genuine delivery',
            );
        }
    }

    /** §9.4.5's "webhook ingestion per integration" limiter is attached. */
    public function test_the_route_is_rate_limited(): void
    {
        $this->assertContains(
            'throttle:webhooks',
            $this->webhookRoutes()[0]->gatherMiddleware(),
            '§9.4.5 names webhook ingestion in the limiter registry; the one unauthenticated endpoint needs it most',
        );
    }

    /**
     * 🛑 No authentication middleware, and that is deliberate rather than
     * an omission.
     *
     * The HMAC **is** the credential. A bearer token in front of it would
     * make the endpoint unreachable by every provider in §8.3.1, and the
     * natural "fix" for that is an exemption — which is the unsigned
     * endpoint again, arriving by a different route.
     */
    public function test_the_route_carries_no_bearer_authentication(): void
    {
        $middleware = $this->webhookRoutes()[0]->gatherMiddleware();

        foreach (['auth', 'api.token', 'tenant'] as $forbidden) {
            $this->assertNotContains($forbidden, $middleware);
        }
    }

    /** @return list<RoutingRoute> */
    private function webhookRoutes(): array
    {
        $found = [];

        foreach (Route::getRoutes()->getRoutes() as $route) {
            $action = $route->getAction('controller');

            if (is_string($action) && str_contains($action, WebhookController::class)) {
                $found[] = $route;
            }
        }

        return $found;
    }
}
