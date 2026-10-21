<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth;

/**
 * The dashboard scope chain: installation → organisation → collection → project.
 *
 * §8.13.1 fixes this chain, and §12.1 fixes how it resolves: **additive union**,
 * not nearest-wins. A request legitimately spans all four, and a reader holding
 * `org_member` on the organisation plus `project_admin` on one project has the
 * union of both capability sets, not whichever the lookup happened to find
 * first.
 *
 * §12.1 records why `spatie/laravel-permission` is rejected rather than leaving
 * it to be relitigated: its teams mode carries a single ambient integer team id
 * with a documented ordering gotcha in queued jobs, and it cannot express one
 * request unioning four scopes. Laravel's `Gate` and policies are the only call
 * site.
 *
 * `Collection` has no table in Phase 02 — collections arrive with hosting
 * (§8.2.5) — but the case exists from the start because `role_assignments`
 * stores `scope_type` (§10.1). Adding an enum case later would mean migrating
 * stored values; reserving it costs nothing.
 */
enum Scope: string
{
    case Installation = 'installation';
    case Organisation = 'organisation';
    case Collection = 'collection';
    case Project = 'project';

    /**
     * Position in the chain, broadest first.
     *
     * Used for presentation and for sanity checks on assignment, never to pick
     * a winner: §12.1 unions, so there is no precedence to compute. A comparison
     * here is about whether an assignment makes sense, not about who wins.
     */
    public function depth(): int
    {
        return match ($this) {
            self::Installation => 0,
            self::Organisation => 1,
            self::Collection => 2,
            self::Project => 3,
        };
    }

    /**
     * Whether a scope of this type names a specific row.
     *
     * The installation is the singleton every installation already is, so its
     * assignments carry a NULL `scope_id`. Everything else must name its
     * subject, and the migration enforces that pairing with a CHECK constraint
     * rather than trusting callers.
     */
    public function requiresSubjectId(): bool
    {
        return $this !== self::Installation;
    }
}
