<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Models\BuildSkipRule;

/**
 * What {@see SkipRuleEvaluator} decided, and which rule decided it.
 *
 * The rule is carried because §8.5.4 settles a skipped request with a stable
 * identifier, and an operator staring at a version that is not rebuilding
 * needs to know WHICH of their rules said no. "Skipped" without the rule is
 * the state that takes an afternoon to debug.
 */
final readonly class SkipDecision
{
    public function __construct(
        public SkipEffect $effect,
        public ?BuildSkipRule $rule,
    ) {}

    public function skips(): bool
    {
        return $this->effect === SkipEffect::Skip;
    }

    /**
     * The §8.1.11 identifier for `build_requests.outcome_identifier`.
     *
     * The rule's position rather than its id, because the identifier is read
     * by a human in a list and `skipped.rule_3` points at a row they can
     * see. The id would be correct and useless.
     */
    public function identifier(): string
    {
        return $this->rule === null
            ? 'skipped.rule_matched'
            : 'skipped.rule_'.$this->rule->position;
    }
}
