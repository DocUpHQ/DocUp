<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

/**
 * §8.5.4's four pre-dispatch filter shapes.
 *
 * > "ordered pre-dispatch skip rules (branch/tag regex, changed-path globs,
 * > commit-message regex, PR label) resolving to `skipped` and never
 * > `failed`"
 *
 * Four cases, named for what they read rather than for what they do, because
 * {@see SkipEffect} already says what they do and a `skip_on_path` case
 * would make the "build only when docs changed" rule unexpressible.
 */
enum SkipRuleKind: string
{
    case BranchTagRegex = 'branch_tag_regex';
    case ChangedPaths = 'changed_paths';
    case CommitMessageRegex = 'commit_message_regex';
    case PrLabel = 'pr_label';

    /**
     * Whether this kind reads the changed-file arrays.
     *
     * 🛑 §8.5.4: "A changed-path skip rule MUST NOT be applied to a payload
     * detected as truncated." The evaluator asks this question rather than
     * comparing against the enum case inline, so adding a fifth path-reading
     * kind cannot forget the rule.
     */
    public function readsChangedPaths(): bool
    {
        return $this === self::ChangedPaths;
    }
}
