<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth;

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
