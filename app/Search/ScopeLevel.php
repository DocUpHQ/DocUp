<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

use App\Auth\AccessLevel;

/**
 * 🛑 §8.12.21's "visibility scope identifier", computed — and **not** a
 * decision.
 *
 * §12.3 is explicit that the lattice's four columns are never collapsed: "No
 * column in this lattice is ever derived at read time from another; all four
 * are stored and all four are authoritative at decision time." So a class that
 * conjoins them needs to say clearly what it is for, or it becomes the second
 * decider §12.3 exists to prevent.
 *
 * What this is for: §8.12.21 requires every search document to carry a
 * visibility scope "as a mandatory server-side filter", and §8.16.6 gives the
 * measured reason — a `MATCH … AGAINST` at 200,000 sections costs p95 80 ms
 * with a scope predicate and 10 ms without, and the cost "scales with
 * **match-set size**". A filter is how 199,000 sections are refused in SQL
 * instead of in PHP.
 *
 * 🛑 **The decision still runs.** `SearchQuery` asks `ReaderGate::authorise()`
 * per project per query, with the real four columns, before any of these values
 * is used — and it asks for `AccessSurface::Search`, so §8.12.21's generation
 * gate applies. This value's only job is to make the SQL narrow. If it were
 * ever wrong in the **weak** direction it would widen the set the decision then
 * refuses; if it were wrong in the strong direction it would hide a document
 * the decision would have allowed. Both are visible failures and neither is a
 * disclosure, because nothing is served on the strength of this number alone.
 *
 * An architecture test asserts this class is never called from a controller.
 */
final readonly class ScopeLevel
{
    /**
     * The strongest of a set of levels — the conjunction §12.3 describes.
     *
     * 🛑 **Strongest wins, and an empty set is `Restricted`.** A conjunction of
     * nothing is not "public": it is a caller that failed to supply the columns,
     * and the only safe reading of a missing constraint is the strongest one.
     * `ReaderGate::level()` takes the same direction for an unrecognised stored
     * string and says why.
     */
    public static function strongestOf(?AccessLevel ...$levels): AccessLevel
    {
        $strongest = null;

        foreach ($levels as $level) {
            if (! $level instanceof AccessLevel) {
                continue;
            }

            if (! $strongest instanceof AccessLevel || $level->stricter($strongest)) {
                $strongest = $level;
            }
        }

        return $strongest ?? AccessLevel::Restricted;
    }

    /**
     * A stored lattice string as a level, failing closed.
     *
     * `restricted` for anything unrecognised — a value this release has not
     * been taught, a hand-edited row, a future migration's fifth level. The
     * same direction and the same reason as `ReaderGate::level()`.
     */
    public static function fromStored(?string $stored): AccessLevel
    {
        if ($stored === null || $stored === '') {
            return AccessLevel::Restricted;
        }

        return AccessLevel::tryFrom($stored) ?? AccessLevel::Restricted;
    }

    /**
     * §12.3's `inherit` resolution for a mount exposure.
     *
     * 🛑 `inherit` means "take the project's value", and an unrecognised value
     * resolves to the project's too rather than to `public` —
     * `AccessRequest::resolvedMountExposure()` is the authority and this
     * mirrors it exactly. Mirrored rather than called because that method is on
     * a request object the indexer has no business building: there is no reader
     * here, and an `AccessRequest` with a synthetic anonymous reader in it
     * would be a decision shaped like a calculation.
     */
    public static function resolveExposure(?string $stored, AccessLevel $projectVisibility): AccessLevel
    {
        if ($stored === null || $stored === '') {
            return $projectVisibility;
        }

        return AccessLevel::tryFrom($stored) ?? $projectVisibility;
    }
}
