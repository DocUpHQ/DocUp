<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

use App\Http\Middleware\AuthenticateApiToken;
use App\Http\Middleware\EnforceSessionLifetime;
use App\Http\Middleware\HandleInertiaRequests;
use App\Http\Middleware\RequireRecentAuthentication;
use App\Http\Middleware\RequireTokenCapability;
use App\Http\Middleware\ResolveOrganisation;
use App\Http\Middleware\SetLocale;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Route;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        /*
         * 🛑 `using:` rather than `web:` + `then:`, because the ORDER matters
         * and registration order is most of what decides matching.
         *
         * 🛑 **Most, not all** — Phase 19 measured the exception and this
         * comment used to state the rule too strongly. A route that
         * declares a **domain** is matched ahead of every route that does
         * not, whatever order they were registered in; order governs only
         * among routes that are alike in that respect. The documentation
         * groups below are all domain-scoped, so order decides between
         * them; `routes/edge.php` had to be given a wildcard domain of its
         * own before being required first meant anything at all.
         *
         * The documentation routes are domain-scoped (SPEC 8.1.4) and must be
         * registered FIRST. With the dashboard first, its unconstrained `/` and
         * Fortify's unconstrained `/login` matched on documentation hosts too:
         * a reader asking a documentation host for `/` was redirected to the
         * dashboard's login page, and `/login` inside a documentation tree would
         * have served the dashboard's own form on the attacker-controlled
         * origin SPEC 8.1.4 exists to keep separate. Registering the
         * domain-scoped routes first costs nothing — they cannot match the
         * dashboard host — and closes both.
         *
         * routes/api.php is required rather than passed as `api:` so its prefix
         * and middleware come from the file. Laravel's `api:` helper applies its
         * own `api` prefix and group, which would have produced /api/api/v3 and
         * attached the stateless group to routes that declare their own —
         * SPEC 8.21.2's bearer authentication is ours, not the framework's.
         */
        using: function (): void {
            /*
             * 🛑 §8.10.18: "`/.well-known/acme-challenge/*` MUST be matched
             * **before** the documentation catch-all, the canonical redirect
             * and the HTTPS redirect." And §20.2's `/_/edge/*` pair, which
             * the proxy calls during a TLS handshake.
             *
             * 🛑 **This line is necessary and not sufficient**, and Phase 19
             * measured why. Registration order governs only among routes
             * that are alike: a route declaring a **domain** is matched
             * ahead of every route that does not, whatever order they were
             * registered in. So `routes/edge.php` declares a wildcard domain
             * of its own — the comment at the top of that file sets out
             * both silent failures that follow from omitting it — and this
             * `require` is what puts it first within that bucket.
             */
            require __DIR__.'/../routes/edge.php';

            require __DIR__.'/../routes/docs.php';

            Route::middleware('web')->group(__DIR__.'/../routes/web.php');

            require __DIR__.'/../routes/api.php';
        },
        commands: __DIR__.'/../routes/console.php',

        /*
         * 🛑 §8.5.22's optional WebSocket profile needs its channel
         * authorisation registered whether or not a broadcaster is
         * configured — a private channel whose callback is missing is a
         * channel Laravel refuses, which looks identical to a channel
         * nobody secured until the day somebody enables the profile and
         * it does not work. Registering it costs one closure and keeps
         * the boundary in the repository rather than in the overlay.
         */
        channels: __DIR__.'/../routes/channels.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        // 🛑 One call. Two separate web(append:) calls did not accumulate — the
        // second replaced the first, so EnforceSessionLifetime silently never
        // ran and every §8.13.3 expiry test returned 200. The failure mode is
        // the dangerous direction: a session control that is configured,
        // reviewed, and absent at runtime.
        $middleware->web(append: [
            HandleInertiaRequests::class,
            SetLocale::class,
            // §8.13.3: on the whole group, because an idle or expired session
            // must end on ANY request, not only the routes someone remembered.
            EnforceSessionLifetime::class,
        ]);

        // 🛑 An alias, not appended globally. Declaring the §8.2.1 tenancy
        // context on every request would mean guessing a tenant for routes
        // that have none — login, the health check — and a guessed tenant is
        // the failure the context throws to prevent. Routes opt in.
        $middleware->alias([
            'tenant' => ResolveOrganisation::class,
            'stepup' => RequireRecentAuthentication::class,
            // SPEC 8.21.2: bearer tokens. An alias for the same reason `tenant`
            // is one - the API declares its own authentication and the web
            // group must not inherit it.
            'api.token' => AuthenticateApiToken::class,
            'token.can' => RequireTokenCapability::class,
        ]);

        /*
         * 🛑 And it MUST run before SubstituteBindings.
         *
         * Route-model binding resolves `{project}` through the §8.2.1 global
         * scope, which is what makes §8.2.2's "404, never 403" free. But
         * SubstituteBindings sits in the `web` group, so by default it runs
         * BEFORE route middleware like `tenant` — binding happened with no
         * context declared, and every request died with
         * TenancyContextMissing instead of resolving.
         *
         * Worth noting how that failed: loudly, with a 500, because the context
         * throws when undeclared. Had it failed open it would have bound the
         * project from the whole table and served another tenant's row — the
         * exact leak this phase exists to prevent, caused by middleware
         * ordering and invisible in every test that did not cross a tenant
         * boundary.
         */
        $middleware->prependToPriorityList(
            before: SubstituteBindings::class,
            prepend: ResolveOrganisation::class,
        );

        /*
         * 🛑 The API middleware is deliberately NOT in the priority list.
         *
         * Adding AuthenticateApiToken to it looked like the same fix, and it
         * was the opposite: the priority list re-sorts every middleware on the
         * route, which hoisted `throttle:api` ahead of authentication. The
         * limiter then never saw a token, so SPEC 8.21.2's per-token limit
         * silently degraded to the anonymous per-IP one on every request — a
         * control that is configured, reviewed and not doing its job, which is
         * the failure mode this file already carries two other warnings about.
         *
         * The API routes need no help with ordering: they declare
         * `['api.token', 'throttle:api']` and carry no SubstituteBindings,
         * because the publish controller resolves its own models (so that one
         * 404 covers every out-of-reach case, per SPEC 8.2.2).
         */

        // 🛑 SPEC 8.9.5 / 9.3.8: TrustHosts' default trusts subdomains of
        // APP_URL, which would hand a documentation host standing it must not
        // have. The allowlist is explicit and comes from the origin config.
        $middleware->trustHosts(at: fn () => array_values(array_filter([
            config('docup.origins.app'),
        ])));
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );
    })->create();
