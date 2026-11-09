<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Federation;

use App\Readers\Grants\GrantMinter;
use App\Readers\ReaderSessions;
use App\Support\Epoch;

/**
 * 🛑 §8.12.26's honest number: how long after a deprovisioning a reader can
 * still read.
 *
 * > "The `ProvisioningDriver` seam ships in v1 and the documentation states the
 * > deprovisioning latency **honestly**: epoch bump plus grant TTL plus the
 * > refresh-session ceiling."
 *
 * ## 🛑 Why this is a computation and not a sentence in a document
 *
 * §8.12.15 is explicit: "Revocation bounds MUST be taken from the one
 * invalidation registry in §10.8 and MUST NOT be restated as a number anywhere
 * else." A latency written into the operator documentation as "about ten
 * minutes" is a number that stops being true the day somebody changes
 * {@see GrantMinter::MAX_TTL_SECONDS} — and nothing fails, because prose does
 * not fail. So the documentation asks this class and prints what it says, and
 * the only numbers in the system are the three constants that own them.
 *
 * ## The three components, and which is which
 *
 * | Component | Owner | Why it is in the sum |
 * |---|---|---|
 * | the epoch bump | §10.8 via {@see Epoch::Identity} | At Tiers A and B this is **one request** — the decision is made in the application against the current epoch — so it contributes nothing. At Tier C it is the epoch-feed interval, which is why §8.12.13 refuses Tier C without the feed |
 * | the grant TTL | {@see GrantMinter::MAX_TTL_SECONDS} | §8.12.11's `exp ≤ 10 minutes`. An unexpired grant is verified at the edge with no database round-trip, so a deprovisioned reader holding one keeps reading until it expires |
 * | the refresh-session ceiling | {@see ReaderSessions::ABSOLUTE_SECONDS} | 🛑 **Not** in the sum, and this is the part that is easy to get wrong — see below |
 *
 * ## 🛑 Why the session ceiling is NOT added, although §8.12.26 names it
 *
 * The requirement lists three terms and the honest bound is **not their sum**,
 * because the session is revoked rather than left to expire: deprovisioning
 * ends the reader's `docs_sessions` rows, and a session that cannot mint a new
 * grant cannot extend the window past the grant it already holds. Adding
 * twenty-four hours would overstate the latency by a factor of 144.
 *
 * So the ceiling is what the bound would be **if sessions were not revoked** —
 * and {@see self::ifSessionsSurvived()} returns it, because an operator
 * evaluating this product against an offboarding requirement is entitled to
 * know what the mechanism rests on. §8.12.26 asks for honesty, and the honest
 * statement is both numbers with the reason the smaller one holds.
 */
final readonly class ProvisioningLatency
{
    /**
     * The bound at Tier A and Tier B.
     *
     * 🛑 The grant TTL alone. §8.12.15: "at Tier A and Tier B, revoking a
     * session or editing a policy takes effect on the **next request**, because
     * the decision is made in the application against the current epoch" — so
     * the epoch bump costs nothing, and what is left is the grant a reader is
     * already holding.
     */
    public static function seconds(): int
    {
        return GrantMinter::MAX_TTL_SECONDS;
    }

    /**
     * The bound at Tier C, where the edge decides from a feed.
     *
     * 🛑 Needs the epoch-feed interval, which is **installation
     * configuration** — and when it is unset, Tier C is refused outright
     * (§8.12.13), so there is no bound to state rather than an unbounded one.
     * Null says that; a large number would read as an answer.
     */
    public static function secondsAtTierC(): ?int
    {
        $feed = config('docup.edge.epoch_feed_seconds');

        if (! is_int($feed) && ! (is_string($feed) && ctype_digit($feed))) {
            /*
             * 🛑 Unset means "not configured", which is what `doctor` refuses
             * Tier C for. Returning `seconds()` here would claim Tier B's bound
             * for a tier that does not have it.
             */
            return null;
        }

        return self::seconds() + (int) $feed;
    }

    /**
     * 🛑 What the bound would be if deprovisioning did not revoke sessions.
     *
     * Published because §8.12.26 asks for the latency stated honestly, and
     * "ten minutes" is only true while {@see ReaderProvisioning::deprovision()}
     * keeps revoking sessions. An operator comparing this product against an
     * offboarding requirement should be able to see what the smaller number
     * rests on — and the next person to consider making deprovisioning lazy
     * should see what it would cost.
     */
    public static function ifSessionsSurvived(): int
    {
        return GrantMinter::MAX_TTL_SECONDS + ReaderSessions::ABSOLUTE_SECONDS;
    }

    /**
     * The sentence the operator documentation prints.
     *
     * 🛑 Generated rather than written, so it cannot drift from the constants.
     * `docs/operator/docs/access.md` asks for this; nothing restates it.
     */
    public static function explain(): string
    {
        $tierC = self::secondsAtTierC();

        return 'A deprovisioned reader stops being able to read within '
            .self::minutes(self::seconds()).' at enforcement Tier A or B — the grant they '
            .'already hold, since their sessions are revoked at once and cannot mint another. '
            .'At Tier C the bound is '
            .($tierC === null
                ? 'unstated, because Tier C is refused without an epoch feed (§8.12.13)'
                : self::minutes($tierC).', the grant TTL plus the epoch-feed interval')
            .'. Were sessions left to expire instead of being revoked, it would be '
            .self::minutes(self::ifSessionsSurvived()).'.';
    }

    /** A duration an operator can read, from seconds. */
    private static function minutes(int $seconds): string
    {
        if ($seconds < 60) {
            return $seconds.' seconds';
        }

        if ($seconds < 3600) {
            return intdiv($seconds, 60).' minutes';
        }

        return intdiv($seconds, 3600).' hours';
    }
}
