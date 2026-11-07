<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Redirects;

/**
 * Why a redirect rule was refused at save time, as a stable identifier.
 *
 * 🛑 §8.1.11 public contract: these reach the audit log, the dashboard, the
 * API and an operator's tooling, so renaming one breaks something outside
 * this repository.
 *
 * 🛑 **Every value here is a save-time refusal, not a runtime one.** §8.11.3
 * and §8.11.4 both insist on that split: a cycle is detected "over the
 * literal rule graph" when the rule is written, and a regex is contained
 * before it ever runs. A rule that could only fail at request time would be
 * a rule the operator finds out about from their readers.
 */
enum RedirectRejection: string
{
    /** The pattern is empty, or not a path at all. */
    case PatternMalformed = 'redirect.pattern_malformed';

    /** 🛑 A prefix rule without `:splat` in the target silently drops the remainder. */
    case SplatMissing = 'redirect.splat_missing';

    /** `:splat` used by a kind that has no remainder to put in it. */
    case SplatNotAvailable = 'redirect.splat_not_available';

    /** The target is not a root-relative path and not an absolute URL. */
    case TargetMalformed = 'redirect.target_malformed';

    /**
     * 🛑 §8.11.2: an absolute target to a hostname this organisation has not
     * proven. The open-redirect primitive, refused.
     */
    case TargetNotProven = 'redirect.target_not_proven';

    /** A scheme other than http or https in an absolute target. */
    case TargetSchemeRefused = 'redirect.target_scheme_refused';

    /** Not one of §8.11.2's four. */
    case StatusRefused = 'redirect.status_refused';

    /** 🛑 §8.11.3: the rule would complete a loop in the literal rule graph. */
    case CycleDetected = 'redirect.cycle_detected';

    /** A rule whose pattern and target are the same path. */
    case SelfRedirect = 'redirect.self_redirect';

    /** 🛑 §8.11.4: over the 255-byte cap. */
    case RegexTooLong = 'redirect.regex_too_long';

    /** 🛑 §8.11.4: a nested quantifier, which is the catastrophic class. */
    case RegexNestedQuantifier = 'redirect.regex_nested_quantifier';

    /** 🛑 §8.11.4: PCRE would not compile it. */
    case RegexUncompilable = 'redirect.regex_uncompilable';

    /** 🛑 §8.11.4's installation-wide kill switch is off. */
    case RegexDisabled = 'redirect.regex_disabled';

    /** The position is taken, or outside the per-project cap. */
    case PositionRefused = 'redirect.position_refused';

    /** §8.11.2's per-project rule cap. */
    case TooManyRules = 'redirect.too_many_rules';

    public function identifier(): string
    {
        return $this->value;
    }
}
