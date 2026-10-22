<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

use App\Http\Middleware\EnforceSessionLifetime;
use App\Http\Middleware\HandleInertiaRequests;
use App\Http\Middleware\RequireRecentAuthentication;
use App\Http\Middleware\ResolveOrganisation;
use App\Http\Middleware\SetLocale;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Routing\Middleware\SubstituteBindings;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
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
