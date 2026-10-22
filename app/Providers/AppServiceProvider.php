<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Providers;

use App\Auth\OrganisationContext;
use App\Http\Middleware\AuthenticateApiToken;
use App\Listeners\StampAuthenticatedSession;
use App\Models\ApiToken;
use App\Support\Origins;
use Illuminate\Auth\Events\Login;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;

final class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        /*
         * 🛑 One instance per container, and NOT a static (§8.2.1, §12.1).
         *
         * §12.1 rejects `spatie/laravel-permission` partly because its teams
         * mode carries "a single ambient integer team id with a documented
         * ordering gotcha in queued jobs": a worker handles jobs for many
         * tenants in sequence, so ambient state set by one job is still set
         * when the next begins. Resolving this from the container keeps the
         * declaration an explicit act rather than process-wide state, and
         * because the undeclared state throws, a job that forgets to declare
         * one fails on its first query instead of quietly reading the previous
         * job's tenant.
         */
        $this->app->singleton(OrganisationContext::class);
    }

    public function boot(): void
    {
        // §8.13.3: regenerate and stamp on every authentication path.
        Event::listen(Login::class, StampAuthenticatedSession::class);

        $this->assertOriginSeparation();
        $this->hardenFrameworkDefaults();
        $this->defineRateLimiters();
    }

    /**
     * §8.21.2: "documented rate limits per token and per IP, and `Retry-After`
     * on 429."
     *
     * 🛑 **Per token AND per IP**, as two limits rather than one. They defend
     * different things, and either alone has a hole:
     *
     * - A per-token limit alone lets somebody with a handful of tokens — or an
     *   unauthenticated flood against the 401 path, which has no token at all —
     *   exhaust the server from one address.
     * - A per-IP limit alone punishes the common legitimate shape, a CI fleet
     *   behind one NAT address, while a distributed caller with one token walks
     *   straight past it.
     *
     * Laravel applies the most restrictive matching limit and adds `Retry-After`
     * to its own 429, so the header requirement needs no code here — but it does
     * need the limiter to exist. Without this method the `throttle:api`
     * middleware throws `MissingRateLimiterException` and every API request is a
     * 500: Laravel 11 removed the `RouteServiceProvider` that used to define
     * `api` by default, so an API route group that names it has to supply it.
     *
     * The numbers are deliberately generous. A publish uploads a whole
     * documentation tree, so a build pipeline makes very few requests and a
     * tight limit would only break someone's monorepo pushing twenty components
     * at once. Abuse of this endpoint is bounded by §8.8.2's caps and §8.8.10's
     * quota, which are the controls that actually cost an attacker something.
     */
    private function defineRateLimiters(): void
    {
        RateLimiter::for('api', function (Request $request): array {
            $token = $request->attributes->get(AuthenticateApiToken::ATTRIBUTE);

            /*
             * Keyed on the token's id, never on the bearer credential. A limiter
             * key reaches the cache, and a cache key containing a live secret is
             * a secret written somewhere nobody is auditing — the same reason
             * §8.21.2's bearer must not travel in a query string.
             */
            $perToken = $token instanceof ApiToken
                ? Limit::perMinute(120)->by('token:'.bin2hex($token->id))
                : Limit::perMinute(30)->by('anon:'.(string) $request->ip());

            return [$perToken, Limit::perMinute(600)->by('ip:'.(string) $request->ip())];
        });
    }

    /**
     * 🛑 SPEC 8.1.4: refuse to boot when the dashboard and documentation origins
     * share a registrable domain. This runs on every boot, including artisan, so
     * a misconfiguration cannot lie dormant until the first reader arrives.
     *
     * Skipped while running unit tests that have not configured origins, because
     * the assertion itself is covered by its own feature test (which sets the
     * config explicitly and asserts both the pass and the throw).
     */
    private function assertOriginSeparation(): void
    {
        if ($this->app->runningUnitTests() && config('docup.origins.app') === null) {
            return;
        }

        Origins::assert(
            config('docup.origins.app'),
            config('docup.origins.docs'),
            config('docup.origins.preview'),
            (bool) config('docup.unsafe.single_origin'),
        );
    }

    /**
     * Close the framework defaults SPEC 9.3.8 names as landmines.
     *
     * TrustHosts is handled in bootstrap/app.php, where the middleware is
     * configured; what belongs here is everything expressible as a runtime
     * default. Argon2id parameters are raised in config/hashing.php, because
     * Laravel's default of m=1024 is roughly 19x below the OWASP floor of
     * 19456 KiB (SPEC 8.12.16).
     */
    private function hardenFrameworkDefaults(): void
    {
        if ($this->app->environment('production')) {
            URL::forceScheme('https');
        }
    }
}
