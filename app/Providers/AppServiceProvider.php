<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Providers;

use App\Auth\OrganisationContext;
use App\Support\Origins;
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
        $this->assertOriginSeparation();
        $this->hardenFrameworkDefaults();
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
