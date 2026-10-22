<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth;

use App\Http\Middleware\RequireTokenCapability;
use App\Models\Project;
use App\Models\User;
use Illuminate\Support\Facades\DB;

/**
 * Resolves dashboard capabilities by **additive union** over the scope chain
 * (§12.1, §8.13.1).
 *
 * 🛑 Union, not nearest-wins. A person holding `org_member` on an organisation
 * and `project_admin` on one of its projects has the capabilities of both. §12.1
 * is explicit that one request legitimately spans four scopes, and that this is
 * why `spatie/laravel-permission` is rejected: it cannot express the union, and
 * its teams mode carries a single ambient team id with a documented ordering
 * gotcha in queued jobs.
 *
 * Queried through the query builder rather than Eloquent, deliberately.
 * `role_assignments` holds installation-scope rows with a NULL
 * `organisation_id`, and the §8.2.1 global tenancy scope would filter exactly
 * those away — so an installation owner would silently lose every capability
 * the moment a tenant context was declared. Authorisation must see the whole
 * table.
 */
final class RoleResolver
{
    /**
     * Every role a user holds that bears on the given target.
     *
     * Passing no target asks only "what does this person hold installation-wide",
     * which is what an installation-level check needs.
     *
     * @return list<Role>
     */
    public function rolesFor(User $user, ?Project $project = null, ?string $organisationId = null): array
    {
        $organisationId ??= $project?->organisation_id;

        // Installation scope always applies: it is the top of the chain.
        $clauses = ['(`scope_type` = ? AND `scope_id` IS NULL)'];
        $bindings = ['installation'];

        /*
         * §8.2.9: a project may opt out of organisation-level inheritance by a
         * single audited flag, and that flag is "the only escape from additive
         * inheritance". So the organisation's assignments are included unless
         * this specific project has opted out.
         *
         * Note the asymmetry: opting out removes the ORGANISATION's grants but
         * never the installation's. An installation owner who could be locked
         * out of a project by a project-level flag would have no way back in,
         * which is how an organisation accidentally takes a project hostage.
         */
        $inherits = $project === null || $project->inherit_organisation_roles;

        if ($organisationId !== null && $inherits) {
            $clauses[] = '(`scope_type` = ? AND `scope_id` = ?)';
            $bindings[] = 'organisation';
            $bindings[] = $organisationId;
        }

        if ($project !== null) {
            $clauses[] = '(`scope_type` = ? AND `scope_id` = ?)';
            $bindings[] = 'project';
            $bindings[] = $project->id;
        }

        /** @var list<object{role: string}> $rows */
        $rows = DB::select(
            'SELECT DISTINCT `role`
               FROM `role_assignments`
              WHERE `subject_type` = ?
                AND `subject_id` = ?
                AND (`expires_at` IS NULL OR `expires_at` > ?)
                AND ('.implode(' OR ', $clauses).')',
            array_merge(['user', $user->id, now()], $bindings),
        );

        $roles = [];

        foreach ($rows as $row) {
            $role = Role::tryFrom($row->role);

            // A stored value the enum does not know is ignored rather than
            // fatal. The column is an ENUM so this needs a schema change to
            // happen at all, and failing closed on one unknown row is better
            // than denying every capability the person legitimately holds.
            if ($role !== null) {
                $roles[] = $role;
            }
        }

        return $roles;
    }

    /**
     * Every capability a user holds **anywhere within** one organisation.
     *
     * 🛑 This is NOT an access decision and must never be used as one. It
     * answers a different question from {@see self::capabilitiesFor()}: not
     * "may you do this to that project" but "do you hold this capability at
     * all, somewhere in this organisation".
     *
     * The distinction is the whole reason it is a separate method. Folding
     * project-scope rows into `rolesFor()` would make a `project_admin` on
     * project A appear to hold administrative capability over project B — a
     * privilege escalation created by a convenience. Per-target resolution
     * stays exactly as narrow as it was.
     *
     * The one legitimate caller is token minting (§8.13.6): "a token may never
     * exceed the capabilities of the person minting it." A project admin
     * genuinely holds `project.version.publish` — at project scope — so
     * refusing to let them mint a token carrying it was wrong, and it made the
     * publish API unusable by precisely the role that should use it. Phase 03
     * found that; the check now asks the right question, and
     * {@see RequireTokenCapability} still re-checks the
     * holder against the specific project on every request. Minting is broad;
     * acting is narrow.
     *
     * @param  string  $organisationId  raw 16 bytes
     * @return list<Capability>
     */
    public function capabilitiesAnywhereIn(User $user, string $organisationId): array
    {
        /** @var list<object{role: string}> $rows */
        $rows = DB::select(
            'SELECT DISTINCT `ra`.`role`
               FROM `role_assignments` AS `ra`
              WHERE `ra`.`subject_type` = ?
                AND `ra`.`subject_id` = ?
                AND (`ra`.`expires_at` IS NULL OR `ra`.`expires_at` > ?)
                AND (
                      (`ra`.`scope_type` = ? AND `ra`.`scope_id` IS NULL)
                   OR (`ra`.`scope_type` = ? AND `ra`.`scope_id` = ?)
                   OR (`ra`.`scope_type` = ? AND `ra`.`scope_id` IN (
                          SELECT `p`.`id` FROM `projects` AS `p`
                           WHERE `p`.`organisation_id` = ? AND `p`.`deleted_at` IS NULL
                      ))
                )',
            [
                'user', $user->id, now(),
                'installation',
                'organisation', $organisationId,
                'project', $organisationId,
            ],
        );

        $capabilities = [];

        foreach ($rows as $row) {
            $role = Role::tryFrom($row->role);

            if ($role === null) {
                continue;
            }

            foreach ($role->capabilities() as $capability) {
                $capabilities[$capability->value] = $capability;
            }
        }

        return array_values($capabilities);
    }

    /**
     * The union of capabilities for a target.
     *
     * @return list<Capability>
     */
    public function capabilitiesFor(User $user, ?Project $project = null, ?string $organisationId = null): array
    {
        $capabilities = [];

        foreach ($this->rolesFor($user, $project, $organisationId) as $role) {
            foreach ($role->capabilities() as $capability) {
                $capabilities[$capability->value] = $capability;
            }
        }

        return array_values($capabilities);
    }

    /** Whether a user holds a capability on a target. */
    public function allows(
        User $user,
        Capability $capability,
        ?Project $project = null,
        ?string $organisationId = null,
    ): bool {
        foreach ($this->rolesFor($user, $project, $organisationId) as $role) {
            if ($role->can($capability)) {
                return true;
            }
        }

        return false;
    }
}
