<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Automation;

use Carbon\CarbonImmutable;
use Cron\CronExpression;

/**
 * A cron expression in an IANA timezone, with §8.22.13's DST semantics
 * **stated** rather than inherited.
 *
 * > "Scheduled builds MUST take an IANA timezone with explicit DST semantics
 * > (a 02:00 nightly build skips one day and repeats another — the
 * > documentation MUST say which)."
 *
 * 🛑 **What DocUp does, and this is the documentation the requirement asks
 * for:**
 *
 *   - A wall-clock time that **does not exist** on a given day — the
 *     spring-forward gap, where 02:00 becomes 03:00 and the hour between
 *     never happens — is **SKIPPED**. A "nightly at 02:30" schedule in
 *     `America/New_York` does not run on the second Sunday in March. It is
 *     skipped rather than moved to 03:30 because an operator who asked for
 *     02:30 chose a quiet hour, and 03:30 is a different hour that may not
 *     be quiet; because the alternative rule (run at the first instant after
 *     the gap) fires every schedule in the gap simultaneously; and because a
 *     documentation build missing one night is recoverable and a surprise
 *     build during a maintenance window is not.
 *
 *   - A wall-clock time that **occurs twice** — the autumn-back overlap,
 *     where 01:30 happens once in daylight time and again an hour later in
 *     standard time — fires **ONCE, at the FIRST occurrence** (the earlier
 *     UTC instant). Firing twice would mean two builds of the same commit an
 *     hour apart; §8.5.2's digest short-circuit would resolve the second to
 *     `unchanged` in under a second, but "absorbed by a later defence" is a
 *     consequence, not a semantic, and §8.22.13 asks for a semantic.
 *
 * 🛑 The expression is evaluated as **wall clock arithmetic with no
 * timezone**, and only the resulting wall time is resolved into the zone.
 * Handing a zone-aware instant to a cron library delegates both rules above
 * to whatever that library happens to do this release — which for the DST
 * gap has historically been "normalise forward silently", the one behaviour
 * this class exists to refuse.
 */
final readonly class CronSchedule
{
    /**
     * How many non-existent occurrences to step over before giving up.
     *
     * Bounded because an expression naming a single wall-clock minute that
     * falls in the gap (`30 2 8 3 *`, 02:30 on 8 March, in a US zone whose
     * transition is that day) legitimately skips a whole year — and because
     * an unbounded search over a pathological expression is a worker that
     * never returns. Two is the realistic maximum; 64 is the limit nobody
     * should reach.
     */
    private const MAX_SKIPPED = 64;

    private CronExpression $expression;

    private \DateTimeZone $zone;

    /**
     * @throws \InvalidArgumentException when the expression or zone is not valid
     */
    public function __construct(string $expression, string $timezone)
    {
        if (! CronExpression::isValidExpression($expression)) {
            throw new \InvalidArgumentException('not a valid cron expression: '.$expression);
        }

        /*
         * 🛑 Validated against PHP's own IANA database rather than a regex.
         * A zone the database does not know is a schedule that would resolve
         * every wall time to UTC without saying so, which is the quiet kind
         * of wrong: the build runs, five hours early, for ever.
         */
        if (! in_array($timezone, \DateTimeZone::listIdentifiers(), true)) {
            throw new \InvalidArgumentException('not an IANA timezone: '.$timezone);
        }

        $this->expression = new CronExpression($expression);
        $this->zone = new \DateTimeZone($timezone);
    }

    /**
     * The next UTC instant strictly after `$after`, or null if none is
     * reachable within {@see MAX_SKIPPED} non-existent occurrences.
     *
     * 🛑 **Strictly after**, which is what stops a missed tick from firing
     * repeatedly: the scheduler stores this value and asks for the next one
     * from it, so a worker that was down for an hour produces one catch-up
     * run and then resumes, rather than one run per minute it missed.
     */
    public function nextAfter(CarbonImmutable $after): ?CarbonImmutable
    {
        // The wall clock in the schedule's own zone, carried in a UTC-flagged
        // value so the cron library does pure calendar arithmetic and never
        // sees a transition.
        $cursor = new \DateTime(
            $after->setTimezone($this->zone)->format('Y-m-d H:i:s'),
            new \DateTimeZone('UTC'),
        );

        for ($attempt = 0; $attempt < self::MAX_SKIPPED; $attempt++) {
            $candidate = $this->expression->getNextRunDate($cursor, 0, false);
            $wall = $candidate->format('Y-m-d H:i:s');

            $resolved = new \DateTimeImmutable($wall, $this->zone);

            /*
             * 🛑 The gap test. PHP normalises a non-existent wall time
             * forward — 02:30 on a spring-forward Sunday becomes 03:30 — so
             * a round trip that comes back different is a time that did not
             * exist. Skipped, per the semantics above.
             *
             * An ambiguous time needs no test: PHP resolves a repeated wall
             * clock to its FIRST occurrence, which is the semantic this
             * class documents, and the round trip matches.
             */
            if ($resolved->format('Y-m-d H:i:s') === $wall) {
                return CarbonImmutable::createFromTimestampUTC($resolved->getTimestamp());
            }

            $cursor = $candidate;
        }

        return null;
    }

    /** Whether an expression and a zone would be accepted. */
    public static function isValid(string $expression, string $timezone): bool
    {
        return CronExpression::isValidExpression($expression)
            && in_array($timezone, \DateTimeZone::listIdentifiers(), true);
    }
}
