<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

use App\Auth\OrganisationContext;
use App\Models\Domain;
use App\Notifications\DomainFailing;
use Illuminate\Support\Carbon;

/**
 * 🛑 §8.10.6's daily re-verification and its state machine.
 *
 * > "Verified domains MUST be re-verified daily with exponential backoff
 * > against at least two independent resolvers that must agree, SSRF-hardened,
 * > rejecting private and link-local answers. State MUST progress
 * > `verified → active → failing` (7-day grace, **warning at the first
 * > failure, not the twenty-ninth**) `→ suspended`."
 *
 * 🛑 **"Warning at the first failure, not the twenty-ninth"** is the clause
 * with teeth, and it is a statement about when a human finds out. A system
 * that warns on day 29 of a 30-day window has technically warned; the
 * operator has one day to notice an email, work out which DNS record
 * changed, and get a change through whatever process owns their zone. The
 * warning goes out on the first failed check, and the seven days that follow
 * are for fixing it rather than for discovering it.
 *
 * 🛑 **An unresolvable check moves nothing.** A DoH provider having a bad
 * hour is not evidence about anybody's DNS, and treating it as one would
 * start the seven-day clock on every domain in the installation at once.
 * {@see VerificationResult::isConclusive()} is that distinction and this is
 * the only caller that acts on it.
 */
final readonly class Reverification
{
    /** §8.10.6's grace between the first failure and suspension. */
    public const GRACE_DAYS = 7;

    /** The nominal interval; backoff lengthens it after a failure. */
    public const INTERVAL_HOURS = 24;

    /** How far backoff may push a recheck, so a domain is never abandoned. */
    public const MAX_BACKOFF_HOURS = 168;

    public function __construct(
        private DomainVerifier $verifier,
        private ?OrganisationContext $context = null,
    ) {}

    /**
     * Re-check every domain whose turn has come.
     *
     * @return array{checked: int, passed: int, failing: int, suspended: int, inconclusive: int}
     */
    public function run(?int $limit = null): array
    {
        $tally = ['checked' => 0, 'passed' => 0, 'failing' => 0, 'suspended' => 0, 'inconclusive' => 0];

        $context = $this->context ?? app(OrganisationContext::class);

        /** @var list<Domain> $due */
        $due = $context->acrossAllOrganisations(static fn (): array => array_values(
            Domain::query()
                ->whereIn('state', ['verified', 'active', 'failing'])
                ->whereIn('kind', ['custom', 'apex'])
                ->where(static fn ($query) => $query
                    ->whereNull('next_check_at')
                    ->orWhere('next_check_at', '<=', now()))
                ->orderByRaw('next_check_at IS NULL DESC')
                ->orderBy('next_check_at')
                ->limit($limit ?? 500)
                ->get()
                ->all(),
        ));

        foreach ($due as $domain) {
            $tally['checked']++;

            $outcome = $this->check($domain);
            $tally[$outcome]++;
        }

        return $tally;
    }

    /**
     * One domain, one check, one transition.
     *
     * @return 'passed'|'failing'|'suspended'|'inconclusive'
     */
    public function check(Domain $domain): string
    {
        $result = $this->verifier->check($domain);

        if ($result->passed) {
            $recovered = $domain->state === 'failing';

            $domain->forceFill([
                'state' => 'active',
                'verification_method' => $result->method->value,
                'last_checked_at' => now(),
                'check_failures' => 0,
                'failing_since' => null,
                'next_check_at' => now()->addHours(self::INTERVAL_HOURS),
            ])->save();

            if ($recovered) {
                (new DomainLedger)->record(
                    $domain->organisation_id,
                    $domain->id,
                    $domain->host,
                    'activated',
                    ['recovered' => true],
                );
            }

            return 'passed';
        }

        if (! $result->isConclusive()) {
            /*
             * 🛑 Nothing moves. The check is retried sooner than a daily
             * interval — a provider outage is usually minutes — but the
             * failure counter, the grace clock and the state are all left
             * exactly where they were.
             */
            $domain->forceFill([
                'last_checked_at' => now(),
                'next_check_at' => now()->addHour(),
            ])->save();

            return 'inconclusive';
        }

        return $this->fail($domain, $result);
    }

    /**
     * @return 'failing'|'suspended'
     */
    private function fail(Domain $domain, VerificationResult $result): string
    {
        $failures = $domain->check_failures + 1;
        $failingSince = $domain->failing_since ?? now();

        /*
         * 🛑 The warning goes out HERE, on the first failure, before any
         * state is decided. Putting it after the suspension branch would
         * send it only to the domains that had already run out of grace,
         * which is the twenty-ninth-day behaviour §8.10.6 names.
         */
        if ($domain->state !== 'failing') {
            $domain->forceFill([
                'state' => 'failing',
                'failing_since' => $failingSince,
            ])->save();

            (new DomainLedger)->record($domain->organisation_id, $domain->id, $domain->host, 'failing', [
                'detail' => $result->detail,
                'grace_until' => $failingSince->copy()->addDays(self::GRACE_DAYS)->toIso8601String(),
            ]);

            DomainFailing::dispatch($domain, $result->detail);
        }

        $suspend = $failingSince->copy()->addDays(self::GRACE_DAYS)->isPast();

        $domain->forceFill([
            'state' => $suspend ? 'suspended' : 'failing',
            'suspended_at' => $suspend ? now() : null,
            'failing_since' => $failingSince,
            'last_checked_at' => now(),
            'check_failures' => $failures,
            'next_check_at' => self::backoff($failures),
        ])->save();

        if ($suspend) {
            (new DomainLedger)->record($domain->organisation_id, $domain->id, $domain->host, 'suspended', [
                'failing_since' => $failingSince->toIso8601String(),
            ]);

            return 'suspended';
        }

        return 'failing';
    }

    /**
     * §8.10.6's exponential backoff, capped.
     *
     * Capped because an uncapped exponential stops checking: after a dozen
     * failures the next check would be years away, and a domain whose DNS
     * was fixed would never be noticed. The cap means a recovered domain
     * comes back within a week at worst.
     */
    public static function backoff(int $failures): Carbon
    {
        $hours = min(self::MAX_BACKOFF_HOURS, (int) (self::INTERVAL_HOURS * 2 ** max(0, $failures - 1)));

        return now()->addHours($hours);
    }
}
