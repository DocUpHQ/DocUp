<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth;

/**
 * The session keys the §8.13.3 and §8.13.5 controls read and write.
 *
 * A shared contract with one home, rather than constants on whichever class
 * happened to need them first. The Pest `laravel` preset caught the original
 * arrangement — a listener importing middleware — and it was right to: the
 * listener does not depend on the middleware's behaviour, only on the names of
 * three session keys, and saying so is the difference between a dependency and
 * a coincidence.
 *
 * 🛑 Every consumer treats a missing stamp as expired or unconfirmed, so a code
 * path that forgets to set one fails closed. The alternative — absent meaning
 * "fine" — produces a session that is immortal precisely because of a bug.
 */
final class SessionStamps
{
    /**
     * When authentication happened. The §8.13.3 absolute lifetime is measured
     * from here and renewed by nothing.
     */
    public const AUTHENTICATED_AT = 'docup.authenticated_at';

    /** Last request. Drives the §8.13.3 idle timeout. */
    public const LAST_ACTIVITY_AT = 'docup.last_activity_at';

    /** Last interactive password confirmation. Drives §8.13.5 step-up. */
    public const CONFIRMED_AT = 'docup.password_confirmed_at';

    /**
     * All three, stamped at the current moment.
     *
     * @return array<string, int>
     */
    public static function fresh(): array
    {
        $now = now()->getTimestamp();

        return [
            self::AUTHENTICATED_AT => $now,
            self::LAST_ACTIVITY_AT => $now,
            self::CONFIRMED_AT => $now,
        ];
    }
}
