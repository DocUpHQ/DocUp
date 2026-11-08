<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

/**
 * 🛑 §8.12.22's linter findings, as a closed vocabulary.
 *
 * Codes rather than prose, for the reason §8.22.5 gives about audit payloads
 * and one more that is specific to this table: the findings are **compared
 * between runs**, and free text compares as different every time somebody
 * improves the wording. A linter that cried change whenever a message was
 * rephrased would be a linter nobody reads.
 *
 * ## 🛑 Two kinds of finding, and the split is the design
 *
 * **Static** findings are properties of the policy as it stands tonight. They
 * are stored and they are part of the fingerprint.
 *
 * **Change** findings are properties of the *difference* from last night, and
 * §8.12.22 asks for exactly those: "alerts on reachability **changes**". They
 * are never stored, because storing them would make tomorrow's comparison a
 * comparison of comparisons.
 *
 * A static finding on its own is not an alert. `Shadowed` is true of every
 * deliberately-shadowed rule, every night, for ever — and an operator told the
 * same thing thirty times has learned to ignore the thirty-first, which is the
 * night it mattered.
 */
enum PolicyFinding: string
{
    // ------------------------------------------------------ static findings

    /**
     * 🛑 Unreachable: an earlier rule's selectors cover every URL this one
     * selects, so §8.12.6's first-match-wins means it can never decide.
     *
     * The commonest way a policy stops doing what its author believes, and
     * invisible from the rule itself — the cause is always *another* rule,
     * usually one edited months later by somebody else.
     */
    case Shadowed = 'shadowed';

    /** `not_after` has passed: the rule can never match again. */
    case Expired = 'expired';

    /** `not_before` is in the future. Informational: the operator meant it. */
    case NotYetActive = 'not_yet_active';

    /**
     * 🛑 Names a binding that is no longer in this project's scope — deleted,
     * or moved out of §8.12.3's resolution.
     *
     * The rule still **matches**, so it still consumes the first-match slot;
     * what it can no longer do is be satisfied. The symptom is a project that
     * refuses everybody with `requirement_unsatisfied`, and nothing in the rule
     * says why.
     */
    case BindingMissing = 'binding_missing';

    /**
     * Names a binding that exists and is not `active` (§8.12.19's five states).
     *
     * Distinct from {@see self::BindingMissing} because the remedy is
     * different: one is re-pointing a rule, the other is finishing a binding's
     * verification.
     */
    case BindingNotActive = 'binding_not_active';

    /**
     * 🛑 Names a binding as the wrong **leaf kind** for its driver (§8.12.17).
     *
     * Refused at write time, so reaching this means the binding's type changed
     * under a rule that was valid when it was written. The rule then refuses
     * every reader for ever, and the mismatch is two tables apart.
     */
    case BindingMisclassified = 'binding_misclassified';

    /**
     * No combination of credentials could satisfy the requirement tree.
     *
     * The conclusion of the three binding findings above, computed rather than
     * assumed: a tree may name a missing binding in one branch of an `OR` and
     * still be satisfiable through the other.
     */
    case RequirementUnsatisfiable = 'requirement_unsatisfiable';

    // ------------------------------------------------------ change findings

    /**
     * 🛑 **More readers can read more.** §8.12.22's alert, in the direction
     * that matters.
     *
     * Widening is not the opposite of narrowing in consequence: a rule that
     * narrowed too far produces a support ticket from somebody who cannot read
     * their own documentation, and a rule that widened too far produces
     * nothing at all until it is found by somebody else.
     */
    case Widened = 'widened';

    /** Fewer readers, or less of it. Reported, because an unintended narrowing is an outage. */
    case Narrowed = 'narrowed';

    /**
     * The rule changed in a way whose **direction cannot be established**.
     *
     * 🛑 Reported as unknown rather than guessed. A requirement tree can be
     * rearranged so that the leaf set is identical and the admitted population
     * is not, and an alert that labelled such an edit "narrowed" would be worse
     * than one that said "changed — look at it": the first is read and
     * dismissed.
     */
    case Changed = 'changed';

    /** `reachable` flipped — §8.12.22's words exactly. */
    case ReachabilityChanged = 'reachability_changed';

    /**
     * 🛑 The rule moved. Under first-match-wins, position **is** semantics.
     *
     * Reordering a policy changes which rule decides without changing a single
     * rule, which is why this is a finding of its own rather than a detail.
     */
    case Moved = 'moved';

    /** A rule the linter has not seen before. Not an alert; the baseline. */
    case New = 'new';

    /**
     * Whether this finding means an operator should be told tonight.
     *
     * 🛑 Only the change findings alert, and {@see self::New} does not: a
     * project's first run would otherwise alert on every rule it has, which is
     * how an operator learns to filter the linter's mail.
     */
    public function alerts(): bool
    {
        return match ($this) {
            self::Widened,
            self::Narrowed,
            self::Changed,
            self::ReachabilityChanged,
            self::Moved => true,
            default => false,
        };
    }

    /**
     * Whether this finding means the policy is **broken** rather than changed.
     *
     * Used for the command's exit code, so a monitoring system notices without
     * reading mail. 🛑 {@see self::Shadowed} is absent: a shadow is often
     * deliberate, and failing a nightly job on an intentional configuration is
     * how a nightly job gets disabled.
     */
    public function isFault(): bool
    {
        return match ($this) {
            self::BindingMissing,
            self::BindingNotActive,
            self::BindingMisclassified,
            self::RequirementUnsatisfiable,
            self::Expired => true,
            default => false,
        };
    }

    /** The audit action this finding is recorded under (§8.22.4's dotted names). */
    public function auditAction(): string
    {
        return 'policy.lint.'.$this->value;
    }
}
