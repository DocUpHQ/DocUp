<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

/**
 * Why a policy write was refused — one code per write-time invariant.
 *
 * Refusals are at **write** time throughout, which is §8.12.7's own word
 * ("MUST reject **at write time**") and the only place they are worth anything:
 * at read time the bad rule already exists, and every decision made before
 * somebody noticed has already been served.
 */
enum RequirementRejection: string
{
    /** 🛑 §8.12.7's satisfiability invariant: no identity-bearing leaf is needed. */
    case SatisfiableWithoutIdentity = 'requirement.satisfiable_without_identity';

    /**
     * 🛑 §8.12.6 bounds the tree at **two levels**, and a deeper one is refused.
     *
     * Not an arbitrary limit. §8.12.25 requires an operator to be able to read
     * a rule and say who it admits, and §8.12.7's invariant is decided by
     * evaluating the tree once — which is tractable precisely because the
     * depth is bounded.
     */
    case TooDeep = 'requirement.too_deep';

    /**
     * 🛑 An empty group, which is the vacuous-truth fail-open §8.12.7 names.
     *
     * > "it closes the vacuous-truth fail-open where 'all preconditions pass,
     * > any one identity suffices' is evaluated over an empty identity set."
     *
     * An empty conjunction is true in logic, so `{"all": []}` would admit
     * everybody. Refused at write time **and** evaluated as false
     * ({@see Requirement::satisfiedBy()}), because a defence that exists in
     * only one of those two places is one refactor from being gone.
     */
    case EmptyGroup = 'requirement.empty_group';

    /** A node that is neither a recognised group nor a recognised leaf. */
    case Malformed = 'requirement.malformed';

    /** A leaf naming a driver §8.12.17 does not classify. */
    case UnknownDriver = 'requirement.unknown_driver';

    /** More leaves than §8.12.6's bounded tree is meant to hold. */
    case TooManyLeaves = 'requirement.too_many_leaves';

    /**
     * 🛑 §9.3.2: `cache_mode = 'public'` on a rule that demands a credential.
     *
     * The rule's cache mode is the third input to the single three-way public
     * check, so a rule that required a binding and declared itself publicly
     * cacheable would put a private response into a shared cache — the exact
     * failure §9.3.2's architecture test exists to prevent, arriving as data
     * rather than as code.
     */
    case PublicCacheModeNeedsPublicTerminal = 'requirement.public_cache_needs_public_terminal';

    /** §10.6's hard cap of 50 rules per project. */
    case TooManyRules = 'policy.too_many_rules';

    /** Two rules claiming one position, which first-match-wins cannot resolve. */
    case DuplicatePosition = 'policy.duplicate_position';

    /** A version selector or path pattern shape the evaluator does not know. */
    case MalformedSelector = 'policy.malformed_selector';

    /**
     * 🛑 §8.12.9: "Regex path matching MUST NOT be supported — it either
     * destroys the edge fast path or becomes an enumeration oracle."
     *
     * Refused by shape rather than by trying and failing: a pattern containing
     * regex metacharacters is almost certainly somebody expecting regex, and
     * silently treating it as a literal prefix would make a rule that looks
     * restrictive match nothing at all.
     */
    case RegexPathPattern = 'policy.regex_path_pattern';

    /** 🛑 §12.3: a `mount_exposure` override that would widen access. */
    case ExposureWidens = 'policy.exposure_widens';
}
