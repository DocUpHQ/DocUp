<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

/**
 * Why a reader request was answered the way it was — one stable code per
 * conjunct of §12.3.
 *
 * 🛑 **One code per conjunct, and the correspondence is deliberate.** §12.3
 * writes the decision as six things that must all hold; if the refusal said
 * only "denied", an operator debugging a 404 would have six candidates and no
 * way to choose between them, and §8.12.25's simulator — "as this identity, on
 * this URL — allow, by rule 7, satisfied by binding X" — could not be built at
 * all.
 *
 * 🛑 These codes are recorded in `access_decisions.reason_code` and in the
 * audit chain, where §8.22.5 requires "a stable code, never free text". They
 * are **not** sent to the reader: §8.12.23 makes the response "the project's
 * `deny_status` with no `WWW-Authenticate` header" and §8.2.2 makes a
 * cross-tenant refusal indistinguishable from absence, so a reason code in a
 * response body would be the enumeration oracle the rest of §8.12 is built to
 * avoid. {@see AccessDecision::header()} carries the code only where §7.4's
 * `X-DocUp-` family is already stripped from inbound requests and the value is
 * for the operator's own logs.
 */
enum AccessReason: string
{
    /** Allowed. The satisfying leaf and the rule are on the decision. */
    case Allowed = 'allowed';

    /**
     * 🛑 §8.2.10's kill switch refused it: "a project at `members` serves
     * nothing publicly however permissive a version or a reader-policy rule
     * is". First conjunct, first code.
     */
    case ProjectVisibility = 'project_visibility';

    /**
     * No rule matched, so §8.12.6's "policy default effect **deny**" applied.
     *
     * Distinct from {@see self::PolicyEmpty} because they need different
     * operator responses: no match means the selectors are wrong, no rules
     * means nobody has written one.
     */
    case PolicyDefaultDeny = 'policy_default_deny';

    /**
     * 🛑 §8.12.19: "A zero-rule policy MUST deny with a red banner."
     *
     * A policy row with no rules is the state a project is in between "reader
     * authentication was switched on" and "somebody said who may read" — and
     * the requirement makes it deny, loudly, rather than fall back to the
     * project's own visibility.
     */
    case PolicyEmpty = 'policy_empty';

    /** The first matching rule's effect was `deny`. First-match-wins (§8.12.6). */
    case RuleDenied = 'rule_denied';

    /** A matching allow rule whose requirement tree the reader did not satisfy. */
    case RequirementUnsatisfied = 'requirement_unsatisfied';

    /** §8.6.2's version visibility refused it. */
    case VersionVisibility = 'version_visibility';

    /** 🛑 §8.10.1's per-domain exposure refused it — narrowing only, never widening. */
    case MountExposure = 'mount_exposure';

    /** 🛑 §8.7.7's component ceiling, re-checked after mount matching. */
    case ComponentMinAccess = 'component_min_access';

    /**
     * 🛑 §12.3's last conjunct: a share link or bearer token whose scope does
     * not cover this (project, version, path).
     */
    case ScopeMismatch = 'scope_mismatch';

    /**
     * 🛑 §8.12.21: search is disabled while its generation lags the policy
     * generation. Fail closed (§10.8).
     */
    case SearchGenerationStale = 'search_generation_stale';

    /**
     * 🛑 §8.12.19: "A degraded binding MUST **deny** with a branded 503 naming
     * the binding … never fall back to another provider, never to public."
     */
    case BindingDegraded = 'binding_degraded';

    /**
     * A credential was presented and rejected — §8.12.23's case (a), which is
     * one of exactly two cases permitting a 401.
     */
    case CredentialRejected = 'credential_rejected';

    /**
     * The resource's existence is already public — §8.12.23's case (b). Only
     * its content requires authentication, so a challenge discloses nothing.
     */
    case AuthenticationRequired = 'authentication_required';

    /** Whether this outcome is an allow. */
    public function isAllow(): bool
    {
        return $this === self::Allowed;
    }
}
