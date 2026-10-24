<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Auth\Role;
use App\Models\Project;
use App\Models\User;
use Illuminate\Support\Facades\DB;

/**
 * Who hears about a project's builds (§8.18.2, §8.5.17).
 *
 * 🛑 **This is a floor, not the notification system.** §8.18.1's event
 * catalogue, per-user subscriptions, digests and unsubscribe handling are
 * Phase 33's; §17 asks Phase 08 only for "build-failure email" and for
 * the governor to "email the owner". Resolving that against the role
 * assignments that already exist is the smallest thing that is actually
 * true, and it will be replaced wholesale rather than extended.
 *
 * 🛑 **Administrative roles only.** Mailing every member of an
 * organisation about one broken branch is how people learn to filter a
 * notification before the system that sends it is finished — and §8.22.8
 * makes recipient lists personal data with their own retention, so a
 * wider list is a larger thing to hold, not merely a noisier one.
 */
final class ProjectOwners
{
    /**
     * @return list<User>
     */
    public static function of(Project $project): array
    {
        $roles = [
            Role::ProjectAdmin->value,
            Role::OrgAdmin->value,
            Role::InstallationOwner->value,
        ];

        /*
         * One query across the three scopes a role can be granted at.
         * Written out rather than assembled from a resolver, because the
         * resolver answers "may this user do X" and the question here is
         * the inverse — "who are the users" — which no capability check
         * can answer without iterating every account.
         */
        /** @var list<object{subject_id: string}> $rows */
        $rows = DB::select(
            'SELECT DISTINCT `ra`.`subject_id`
               FROM `role_assignments` AS `ra`
              WHERE `ra`.`subject_type` = ?
                AND `ra`.`role` IN (?, ?, ?)
                AND (`ra`.`expires_at` IS NULL OR `ra`.`expires_at` > ?)
                AND (
                      (`ra`.`scope_type` = ? AND `ra`.`scope_id` IS NULL)
                   OR (`ra`.`scope_type` = ? AND `ra`.`scope_id` = ?)
                   OR (`ra`.`scope_type` = ? AND `ra`.`scope_id` = ?)
                )',
            [
                'user', ...$roles, now(),
                'installation',
                'organisation', $project->organisation_id,
                'project', $project->id,
            ],
        );

        if ($rows === []) {
            return [];
        }

        $ids = array_map(static fn (object $row): string => (string) $row->subject_id, $rows);

        /** @var list<User> $users */
        $users = User::query()->whereIn('id', $ids)->get()->all();

        return $users;
    }
}
