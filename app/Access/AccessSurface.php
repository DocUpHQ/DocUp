<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

/**
 * The four reader surfaces §17's Phase 21 exit criterion enumerates.
 *
 * > "The full matrix — `{public, private} × {active, hidden} × {member,
 * > non-member, anonymous} × {proxy, download, search, addons}` — asserted at
 * > 100%."
 *
 * 🛑 **A surface is an input to the decision, not a caller of a different
 * decision.** §8.12.21 requires every privacy-sensitive derived surface to be
 * "generated from the **authorised** view", and the way to make that structural
 * rather than remembered is to give the one function an axis for it — so a new
 * surface is a case here and a row in the generated table, not a second
 * authorisation path written by whoever adds it.
 *
 * The axis is not decorative: {@see self::requiresCurrentSearchGeneration()} is
 * true for exactly one of the four, and that asymmetry is §8.12.21's.
 */
enum AccessSurface: string
{
    /** A documentation request: §8.9.8's byte handoff. */
    case Proxy = 'proxy';

    /** §8.5.14's offline formats — PDF, ePub, zipped HTML. */
    case Download = 'download';

    /** §8.16's search, over `search_documents`. */
    case Search = 'search';

    /** §8.15's addons payload: flyout, version list, notices. */
    case Addons = 'addons';

    /**
     * 🛑 §8.12.21: "a project's search MUST be **disabled** while its search
     * generation lags its policy generation".
     *
     * Only `search` answers true, and the reason is the direction of the
     * failure. The search index is a *copy* of the authorisation facts, stamped
     * with the generation it was built under; the other three surfaces read the
     * live rows. So a policy that has just been tightened is already in force
     * for a page request and is **not yet** in force for the index — and
     * serving from a stale index is handing out documents the new policy
     * refuses.
     *
     * §10.8 gives `policy_generation` a "fail closed" staleness for this
     * reason: search returning nothing is an outage, search returning private
     * sections is a disclosure, and only one of those is recoverable.
     */
    public function requiresCurrentSearchGeneration(): bool
    {
        return $this === self::Search;
    }
}
