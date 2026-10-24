<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Versions;

use App\Models\ProjectVersion;

/**
 * Where §8.6.4's two channels point after a reconciliation, and which moved.
 *
 * 🛑 `moved` exists because the exit criterion is about movement rather
 * than about the final state: "Pushing `v2.0.0` creates a version and
 * **moves** `stable`." A caller that only had the pointers would have to
 * remember the previous ones to tell, which is the sort of bookkeeping that
 * ends up wrong in one of the three places that does it.
 *
 * 🛑 Null is a real answer for either channel. §8.6.4's step 5 makes "no
 * `stable` at all" valid and forbids falling back to the default branch,
 * so a null here means the project has no stable release — not that
 * something failed.
 */
final readonly class ChannelOutcome
{
    /** @param  list<string>  $moved  'stable', 'latest', or both */
    public function __construct(
        public ?ProjectVersion $stable,
        public ?ProjectVersion $latest,
        public array $moved = [],
    ) {}

    public function stableMoved(): bool
    {
        return in_array('stable', $this->moved, true);
    }

    public function latestMoved(): bool
    {
        return in_array('latest', $this->moved, true);
    }
}
