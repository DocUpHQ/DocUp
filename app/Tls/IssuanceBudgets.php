<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

use App\Models\IssuanceBudget;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

/**
 * §8.10.13's per-registered-domain budget, as the token bucket the CA runs.
 *
 * > "Issuance budgets MUST be tracked per registered domain with a warning at
 * > 40 and a hard block at 50 per 7 days."
 *
 * 🛑 **§18.20 asked for the limits to be re-read before these numbers were
 * frozen, and the re-read (2026-10-26, against a page last updated
 * 2026-08-05) changed the shape rather than the numbers.** Let's Encrypt
 * states "New Certificates per Registered Domain" as a bucket of **50 with a
 * refill of one per 202 minutes**, global across accounts. The totals agree
 * — 50 × 202 minutes is 7.01 days — but a fixed seven-day window and a
 * token bucket behave differently at exactly the moments that matter:
 *
 *  - a window lets fifty issue in an hour and then refuses for a week;
 *  - a window refuses the fifty-first even after two days of refill, while
 *    the CA by then has fourteen tokens waiting.
 *
 * Modelling the bucket makes this installation's answer the CA's answer, so
 * an operator who is told "blocked" is told something true rather than
 * something conservative by accident.
 *
 * 🛑 The ceiling is **not** raised when an operator has a rate-limit override
 * from the CA. The override is granted per account and per registered domain
 * and DocUp cannot read it; guessing it would turn a hard block into a
 * stream of `urn:ietf:params:acme:error:rateLimited` failures, which cost
 * authorization-failure budget as well.
 */
final readonly class IssuanceBudgets
{
    /** Let's Encrypt's "New Certificates per Registered Domain", as of 2026-08-05. */
    public const int CAPACITY = 50;

    /** One token per 202 minutes, which is where 50 per 7 days comes from. */
    public const int REFILL_MINUTES = 202;

    /**
     * §8.10.13's "warning at 40" — ten tokens left.
     *
     * The comparison is `<=`, because "a warning at 40" means at the
     * fortieth issuance, and the fortieth issuance leaves exactly ten.
     */
    public const int WARN_BELOW = 10;

    public function __construct(private ?Carbon $now = null) {}

    /**
     * Whether one certificate could be issued for this registrable domain.
     *
     * Read-only: this is what the permission endpoint asks, and a permission
     * query must not consume a token — the proxy may ask and then never
     * issue, and a hundred such questions would exhaust a bucket nothing had
     * drawn on.
     */
    public function permits(string $registeredDomain): bool
    {
        return $this->remaining($registeredDomain) >= 1.0;
    }

    /** Tokens available right now, refill included. */
    public function remaining(string $registeredDomain): float
    {
        $budget = IssuanceBudget::query()->where('registered_domain', $registeredDomain)->first();

        if ($budget === null) {
            return (float) self::CAPACITY;
        }

        return $this->levelAt($budget, $this->now());
    }

    /**
     * Take one token, or refuse.
     *
     * 🛑 Serialised with `SELECT … FOR UPDATE`. Two issuances racing on one
     * registrable domain would otherwise both read 1 token and both spend
     * it, which is precisely the case the bucket exists to prevent — and the
     * CA, which is not racing with itself, would refuse the second with a
     * failure that also costs authorization budget.
     *
     * @throws CertificateRefused when the bucket is empty
     */
    public function consume(string $registeredDomain): float
    {
        return DB::transaction(function () use ($registeredDomain): float {
            $now = $this->now();

            $budget = IssuanceBudget::query()
                ->where('registered_domain', $registeredDomain)
                ->lockForUpdate()
                ->first();

            if ($budget === null) {
                $budget = new IssuanceBudget;
                $budget->forceFill([
                    'registered_domain' => $registeredDomain,
                    'tokens' => (string) self::CAPACITY,
                    'tokens_at' => $now,
                ])->save();
            }

            $level = $this->levelAt($budget, $now);

            if ($level < 1.0) {
                $budget->forceFill(['tokens' => $this->decimal($level), 'tokens_at' => $now, 'blocked_at' => $now])->save();

                throw CertificateRefused::of(
                    CertificateRejection::BudgetExhausted,
                    $registeredDomain.' has '.number_format($level, 2).' of '.self::CAPACITY.' tokens',
                );
            }

            $level -= 1.0;

            $budget->forceFill([
                'tokens' => $this->decimal($level),
                'tokens_at' => $now,
                'blocked_at' => null,
                /*
                 * Recorded once rather than recomputed, so the operator is
                 * told at the fortieth issuance rather than at every
                 * issuance after it. Cleared below the threshold so a bucket
                 * that refills and is spent again warns again.
                 */
                'warned_at' => $level <= self::WARN_BELOW ? ($budget->warned_at ?? $now) : null,
            ])->save();

            return $level;
        });
    }

    /** Whether §8.10.13's warning threshold has been crossed and not cleared. */
    public function hasWarned(string $registeredDomain): bool
    {
        return IssuanceBudget::query()
            ->where('registered_domain', $registeredDomain)
            ->whereNotNull('warned_at')
            ->exists();
    }

    /**
     * The bucket's level now: what was stored, plus the refill since.
     *
     * Capped at capacity, because a bucket that kept filling while nothing
     * drew on it would let a quiet month pay for a burst the CA will refuse.
     */
    private function levelAt(IssuanceBudget $budget, Carbon $now): float
    {
        $elapsed = max(0.0, $budget->tokens_at->diffInSeconds($now, absolute: false) / 60.0);

        return min(
            (float) self::CAPACITY,
            (float) $budget->tokens + $elapsed / self::REFILL_MINUTES,
        );
    }

    /** DECIMAL(8,4), as a string: a float round-trip loses the refill. */
    private function decimal(float $level): string
    {
        return number_format(max(0.0, $level), 4, '.', '');
    }

    private function now(): Carbon
    {
        return ($this->now ?? Carbon::now())->copy();
    }
}
