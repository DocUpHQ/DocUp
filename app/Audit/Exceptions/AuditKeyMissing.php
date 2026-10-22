<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Audit\Exceptions;

/**
 * No `k_audit` is configured (§8.22.1).
 *
 * 🛑 Deliberately fatal rather than falling back to `APP_KEY`. A fallback would
 * mean an installation that never set `DOCUP_AUDIT_KEY` still produces a log
 * that looks chained and verifies — while being forgeable by anyone who holds
 * the key the application needs for everyday work, which is the exact property
 * §8.22.1 separates the keys to avoid. A log whose integrity claim is false is
 * worse than no log, because it is believed.
 */
final class AuditKeyMissing extends \RuntimeException
{
    public static function notConfigured(): self
    {
        return new self(
            "No audit key configured (§8.22.1). Set DOCUP_AUDIT_KEY.\n\n"
            ."Generate one:\n"
            ."  php -r \"echo bin2hex(random_bytes(32)), PHP_EOL;\"\n\n"
            ."🛑 It must NOT be APP_KEY, and not derived from it: whoever holds the audit key can\n"
            ."forge a chain that verifies. Back it up separately, and note that losing it does not\n"
            .'destroy the log but does end your ability to prove it was not altered.'
        );
    }
}
