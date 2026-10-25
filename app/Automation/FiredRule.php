<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Automation;

use App\Models\AutomationRule;
use App\Models\ProjectVersion;

/**
 * One §8.6.8 rule that fired, and the version it fired on.
 *
 * Returned so a caller can report what happened without re-querying, and so
 * a test can assert the ORDER of firing — which is the part of §8.6.8 that
 * a count would not catch, and the part that matters because the actions
 * are not commutative.
 */
final readonly class FiredRule
{
    public function __construct(
        public AutomationRule $rule,
        public ProjectVersion $version,
    ) {}
}
