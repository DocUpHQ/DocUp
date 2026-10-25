<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

/**
 * §8.7.14's precedence strategy, as one enum in requirement and schema.
 *
 * > "Output path collisions MUST fail the build by default, naming **both**
 * > contributing sources and the exact path. The policy is one enum in both
 * > the requirement and the schema — `fail` (default), `first_wins` (the
 * > lower `component_sources.priority` wins) or `priority_wins` (the
 * > explicit priority ordering wins, with a tie refused at write time) — and
 * > a precedence strategy MUST be selected explicitly per component."
 *
 * 🛑 `fail` is the default and the reason is in the requirement's own words
 * a clause earlier: a silent winner "is how one team's page disappears
 * behind another's without anyone being told". The two permissive modes
 * exist for the composition that genuinely overlaps on purpose; both leave
 * a record.
 */
enum CollisionPolicy: string
{
    /** 🛑 Refuse, naming both sources and the exact path. */
    case Fail = 'fail';

    /** The lower `component_sources.priority` wins. */
    case FirstWins = 'first_wins';

    /** The explicit priority ordering wins; a tie is refused. */
    case PriorityWins = 'priority_wins';

    /**
     * Whether this policy lets a composition publish with an overlap.
     *
     * `priority_wins` says yes **only** when the priorities differ, which is
     * why the question is asked of the policy and answered by the caller
     * with the two priorities in hand: §8.7.14 refuses a tie, and a tie
     * under `priority_wins` is a composition whose author believed they had
     * expressed an order and had not.
     */
    public function permitsOverlap(): bool
    {
        return $this !== self::Fail;
    }
}
