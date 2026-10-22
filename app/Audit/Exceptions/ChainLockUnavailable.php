<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Audit\Exceptions;

/**
 * Could not take the per-chain write lock in time.
 *
 * 🛑 Failing the whole action is correct here, and the alternative is worse.
 * §8.22.4 commits the mutation and its audit row together, so proceeding
 * without the lock would mean either an unaudited mutation or a forked chain —
 * and a forked chain makes `audit:verify` report tampering where none
 * happened. An operator who learns that verification cries wolf is one who
 * will ignore it when it is right.
 */
final class ChainLockUnavailable extends \RuntimeException
{
    public static function for(string $chainKey, int $seconds): self
    {
        $chain = $chainKey === str_repeat("\x00", 16)
            ? 'the installation chain'
            : 'organisation '.bin2hex($chainKey);

        return new self(
            "Could not acquire the audit chain lock for {$chain} within {$seconds}s.\n\n"
            ."The lock is held for a single insert, so contention means something else is holding\n"
            ."it — usually a long-running transaction that recorded an audit event and has not yet\n"
            .'committed. Look for that rather than raising the timeout.'
        );
    }
}
