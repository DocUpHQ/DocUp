<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Providers;

use App\Domains\AgreeingResolvers;
use App\Egress\AddressGuard;
use App\Egress\TlsHandshakeProbe;
use App\Tls\IssuanceBreaker;
use App\Tls\IssuanceBudgets;
use App\Tls\IssuancePermission;
use App\Tls\PermissionEndpoint;
use App\Tls\PermittedHosts;
use App\Tls\TlsProber;
use Illuminate\Cache\RateLimiter;
use Illuminate\Support\ServiceProvider;

/**
 * Binds §8.10's TLS automation, and enforces §8.10.12 at boot.
 *
 * 🛑 The boot check is the phase's own exit criterion: "Configuring the
 * permission endpoint as HTTPS on a served hostname is **refused at
 * validation**, not discovered at first handshake."
 *
 * Discovering it at first handshake means discovering it never —
 * {@see PermissionEndpoint} spells out why the deadlock produces no log
 * line anywhere. So the installation refuses to start instead, which is the
 * same posture `BuildServiceProvider` takes to §8.5.11's unsandboxed runner
 * and for the same reason: a configuration that cannot work should fail
 * where somebody is watching.
 */
final class TlsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(PermittedHosts::class);

        $this->app->singleton(IssuanceBudgets::class, static fn (): IssuanceBudgets => new IssuanceBudgets);
        $this->app->singleton(IssuanceBreaker::class, static fn (): IssuanceBreaker => new IssuanceBreaker);

        $this->app->singleton(IssuancePermission::class, fn (): IssuancePermission => new IssuancePermission(
            $this->app->make(PermittedHosts::class),
            $this->app->make(IssuanceBudgets::class),
            $this->app->make(IssuanceBreaker::class),
            AgreeingResolvers::fromConfig(),
            $this->app->make(RateLimiter::class),
        ));

        $this->app->singleton(TlsProber::class, fn (): TlsProber => new TlsProber(
            new TlsHandshakeProbe(
                $this->app->make(AddressGuard::class),
                is_int(config('tls.probe.timeout_seconds')) ? config('tls.probe.timeout_seconds') : 5,
            ),
        ));
    }

    public function boot(): void
    {
        /*
         * 🛑 Skipped under the unit-test runner for the reason
         * `BuildServiceProvider` skips its own check: a test that wants to
         * exercise the refusal calls the validator directly, and one that
         * does not should not have to configure TLS to boot. The rule is
         * asserted both ways in `tests/Feature/Tls/PermissionEndpointTest.php`.
         */
        if ($this->app->runningUnitTests()) {
            return;
        }

        $endpoint = config('tls.permission_endpoint');

        PermissionEndpoint::assertUsable(is_string($endpoint) ? $endpoint : '');
    }
}
