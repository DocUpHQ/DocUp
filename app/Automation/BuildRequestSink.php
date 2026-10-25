<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Automation;

use App\Models\BuildRequest;
use App\Models\ProjectVersion;

/**
 * Where §8.6.8's `build` action sends its request.
 *
 * 🛑 An interface rather than a direct call into `App\Builds`, because the
 * dependency would otherwise run the wrong way: the build pipeline already
 * calls the automation engine after a sync, and having the engine call the
 * pipeline back makes the two mutually dependent — which is how a rule that
 * triggers a build ends up triggering the sync that evaluates the rule.
 *
 * The seam is also what makes "a changed-paths rule fires project A and
 * provably does **not** enqueue project B" assertable on the enqueued job
 * list rather than on a side effect three layers down.
 */
interface BuildRequestSink
{
    /**
     * Record a build request for this version.
     *
     * @param  string  $trigger  one of §8.5.3's eight kinds
     */
    public function requestBuild(ProjectVersion $version, string $trigger): ?BuildRequest;
}
