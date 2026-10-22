<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth;

/**
 * How a model relates to the organisation tenancy boundary (§8.2.1).
 *
 * 🛑 §8.2.1 requires an architecture test to fail CI for any model that does
 * not **declare** a posture. Declaration rather than inference is the whole
 * point: a model with no `organisation_id` might be correctly installation-wide
 * or might be a cross-tenant leak nobody noticed, and those two look identical
 * to a tool that guesses. Forcing the author to say which converts a silent
 * omission into a visible claim that a reviewer can disagree with.
 *
 * §14 puts cross-tenant access at the top of the threat model, and §8.2.2 fixes
 * the response: 404, never 403, through the UI, the API and direct identifier
 * access alike. A 403 confirms the row exists, which is itself a leak.
 */
enum TenancyPosture: string
{
    /**
     * Carries `organisation_id` and is filtered by the global scope.
     *
     * The default for anything a tenant can reach. Rows are invisible outside
     * their organisation unless a caller explicitly steps outside the scope.
     */
    case OrganisationScoped = 'organisation_scoped';

    /**
     * Deliberately installation-wide: shared by every tenant, owned by none.
     *
     * `User` is the important example and the one worth understanding. A person
     * is an installation-level identity who may hold roles in several
     * organisations, so scoping the table by organisation would be wrong — it
     * would make one human into several accounts. Their *membership* is
     * org-scoped (`team_members`, `role_assignments`); their identity is not.
     */
    case Installation = 'installation';

    /**
     * Framework-owned plumbing: queue, cache, sessions, migrations.
     *
     * Not DocUp's data model, and named explicitly rather than pattern-matched
     * so that adding one is a visible decision — the same discipline §9.1.3
     * applies to the AUTO_INCREMENT allowlist.
     */
    case Framework = 'framework';

    /** Whether the global organisation scope applies to this posture. */
    public function isScoped(): bool
    {
        return $this === self::OrganisationScoped;
    }
}
