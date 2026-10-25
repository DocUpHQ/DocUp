<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Models\BuildRequest;
use App\Versions\SyncOutcome;

/**
 * What one §8.5.3 `repository_fanout` produced.
 *
 * 🛑 `enqueued` and `skipped` are separate lists rather than one list with a
 * state to inspect, because Phase 11's exit criterion is about the
 * difference: "A changed-paths rule fires project A and provably does
 * **not** enqueue project B, asserted on the enqueued job list." A single
 * list would make the assertion a filter, and a filter that reads the wrong
 * column passes.
 */
final readonly class FanoutOutcome
{
    /**
     * @param  list<BuildRequest>  $enqueued  requests with a job behind them
     * @param  list<BuildRequest>  $skipped  recorded and settled without a build
     * @param  list<SyncOutcome>  $syncs  one per consuming project
     */
    public function __construct(
        public array $enqueued = [],
        public array $skipped = [],
        public array $syncs = [],
    ) {}

    public function total(): int
    {
        return count($this->enqueued) + count($this->skipped);
    }
}
