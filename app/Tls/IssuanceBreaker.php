<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

use App\Models\Domain;
use Illuminate\Support\Carbon;

/**
 * §8.10.13's per-host circuit breaker.
 *
 * > "…plus a per-host circuit breaker with exponential backoff, recorded in
 * > an attempts table…"
 *
 * 🛑 **§18.20's re-read gave this class its first backoff step.** Let's
 * Encrypt's page (2026-08-05) carries two failure limits, not one, and the
 * second is the one that bites:
 *
 *  - *Authorization failures per identifier per account*: **5 per hour**,
 *    refilling one per 12 minutes. Exceed it and that hostname cannot be
 *    validated for the rest of the hour.
 *  - *Consecutive authorization failures per identifier*: capacity 1,152,
 *    refilling one per day and **resetting only on a successful
 *    validation**. Sustained failure therefore accumulates: two a day pauses
 *    the identifier after 1,152 days, five a day after 288.
 *
 * A breaker whose first step was a minute would spend the hourly budget in
 * five minutes and then keep spending the consecutive one every hour for as
 * long as the misconfiguration lasted. So the first step is **fifteen
 * minutes** — four attempts an hour at worst, inside the hourly five — and
 * it doubles from there to a day. The common cause is an operator who
 * pointed a CNAME at the wrong target and will fix it within the day; the
 * breaker's job is to make that cost nothing.
 */
final readonly class IssuanceBreaker
{
    /** 🛑 Four an hour at worst, against a hourly budget of five. */
    public const int FIRST_BACKOFF_MINUTES = 15;

    /** A day. Longer buys nothing: the consecutive bucket refills one a day. */
    public const int MAX_BACKOFF_MINUTES = 1440;

    public function __construct(private ?Carbon $now = null) {}

    /** Whether issuance may be attempted for this hostname right now. */
    public function closed(Domain $domain): bool
    {
        $until = $domain->issuance_blocked_until;

        return $until === null || $until->lessThanOrEqualTo($this->now());
    }

    /**
     * Record a failure and open the breaker for the next interval.
     *
     * @return Carbon when issuance may next be attempted
     */
    public function fail(Domain $domain): Carbon
    {
        $failures = $domain->issuance_failures + 1;
        $until = $this->now()->addMinutes($this->backoff($failures));

        $domain->forceFill([
            'issuance_failures' => $failures,
            'issuance_blocked_until' => $until,
        ])->save();

        return $until;
    }

    /**
     * 🛑 Clear the breaker — and only on a **success**, never on a retry or a
     * timer.
     *
     * The CA's consecutive-failure counter resets on a successful validation
     * and on nothing else, so a breaker that healed itself on elapsed time
     * would come back closed while the CA's count carried on climbing. The
     * two counters have to agree about what "recovered" means.
     */
    public function succeed(Domain $domain): void
    {
        if ($domain->issuance_failures === 0 && $domain->issuance_blocked_until === null) {
            return;
        }

        $domain->forceFill(['issuance_failures' => 0, 'issuance_blocked_until' => null])->save();
    }

    /** 15, 30, 60, … capped at a day. */
    public function backoff(int $failures): int
    {
        $minutes = self::FIRST_BACKOFF_MINUTES * (2 ** max(0, $failures - 1));

        return (int) min(self::MAX_BACKOFF_MINUTES, $minutes);
    }

    private function now(): Carbon
    {
        return ($this->now ?? Carbon::now())->copy();
    }
}
