<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

/**
 * What a two-resolver lookup produced (§8.10.6).
 *
 * 🛑 Three outcomes, not two, and the third is the one that matters. A
 * resolver outage and a withdrawn DNS record are different events with
 * different consequences: the first must leave a verified domain alone, the
 * second must start §8.10.6's seven-day grace. Collapsing them would make
 * every domain in the installation start failing the next time a provider
 * had a bad hour.
 */
enum Outcome: string
{
    /** Both resolvers answered and agreed. */
    case Answered = 'answered';

    /** 🛑 They answered and disagreed — a partially propagated takeover looks like this. */
    case Disagreed = 'disagreed';

    /** Fewer than two resolvers answered at all. Not a failed proof. */
    case Unresolvable = 'unresolvable';
}
