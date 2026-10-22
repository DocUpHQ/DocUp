<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests;

use App\Auth\SessionStamps;
use App\Listeners\StampAuthenticatedSession;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Testing\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    /**
     * Act as a user with a session that looks like a real login.
     *
     * 🛑 Needed because the §8.13.3 and §8.13.5 middleware **fail closed**: an
     * authenticated session with no `authenticated_at` stamp is treated as
     * expired, and one with no `password_confirmed_at` as needing step-up. That
     * is the right behaviour — the alternative is a session that is immortal
     * because something forgot to stamp it — but Laravel's `actingAs()` sets
     * neither, so every feature test would be redirected to the login page.
     *
     * In production the stamps come from {@see StampAuthenticatedSession} on
     * the `Login` event. This mirrors that one listener rather than disabling
     * the middleware, so tests still exercise the real pipeline.
     *
     * The expiry and step-up behaviour is NOT exempted by this: those tests
     * manipulate the stamps directly, which is the only honest way to assert a
     * control that a helper is quietly satisfying for everyone else.
     */
    public function actingAs(Authenticatable $user, $guard = null): static
    {
        parent::actingAs($user, $guard);

        return $this->withSession(SessionStamps::fresh());
    }
}
