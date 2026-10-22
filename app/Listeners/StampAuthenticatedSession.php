<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Listeners;

use App\Auth\SessionStamps;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Session;

/**
 * Stamps a session at authentication (§8.13.3).
 *
 * 🛑 §8.13.3 requires the session identifier to be regenerated **on
 * authentication** — the defence against session fixation, where an attacker
 * plants a known session id in a victim's browser and then holds a session that
 * becomes authenticated when the victim logs in.
 *
 * Driven by the `Login` event rather than written into a controller, because
 * there is more than one way in: a form login now, invitation acceptance and an
 * IdP callback in Phase 25. A stamp that lives in one controller is a stamp the
 * other paths lack. The §8.13.3 middleware treats a missing stamp as expired,
 * so a path that somehow bypassed this fails closed rather than producing an
 * immortal session.
 *
 * Depends on {@see SessionStamps}, not on the middleware. The Pest `laravel`
 * preset flagged the original arrangement and was right to: this listener needs
 * three key names, not any middleware's behaviour.
 */
final class StampAuthenticatedSession
{
    public function handle(Login $event): void
    {
        Session::regenerate();

        /*
         * SessionStamps::fresh() includes the §8.13.5 confirmation stamp, so
         * authenticating counts as confirming the password. Without that, a
         * sensitive action taken seconds after logging in would prompt again —
         * and a product that asks twice in a row teaches people to type their
         * password without reading the page, which is what phishing relies on.
         */
        foreach (SessionStamps::fresh() as $key => $value) {
            Session::put($key, $value);
        }
    }
}
