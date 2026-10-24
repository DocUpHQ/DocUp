<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Versions;

use App\Models\ProjectVersion;

/**
 * What one §8.6.1 sync did.
 *
 * Returned rather than logged, because §8.6.8's automation rules are
 * triggered by version "creation or disappearance" and need to know which
 * is which. A caller that only wanted a count would get one from
 * `count($outcome->created)`; a caller that wants to fire a rule per new
 * version needs the rows.
 *
 * 🛑 **`disappeared` is not `deleted`.** §8.6.15 is categorical that a ref
 * going away deactivates a version rather than removing it, so every row in
 * that list still exists and still serves by direct URL. The field is named
 * for what happened upstream, not for what happened here.
 */
final readonly class SyncOutcome
{
    /**
     * @param  list<ProjectVersion>  $created
     * @param  list<ProjectVersion>  $updated  refs that were already known
     * @param  list<ProjectVersion>  $disappeared  hidden, never deleted
     */
    public function __construct(
        public array $created = [],
        public array $updated = [],
        public array $disappeared = [],
    ) {}

    public function changedAnything(): bool
    {
        return $this->created !== [] || $this->disappeared !== [];
    }

    /** Every version this sync touched, for a caller re-deriving the channels. */
    public function total(): int
    {
        return count($this->created) + count($this->updated) + count($this->disappeared);
    }
}
