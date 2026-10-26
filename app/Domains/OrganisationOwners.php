<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

use App\Auth\Role;
use App\Models\User;
use Illuminate\Support\Facades\DB;

/**
 * Who hears about an organisation's domains (§8.18.2, §8.10.6).
 *
 * 🛑 **A floor, like `App\Builds\ProjectOwners`, and it will be replaced by
 * the same thing.** §8.18.1's event catalogue, per-user subscriptions,
 * digests and unsubscribe handling are Phase 33's. What Phase 18 cannot
 * defer is §8.10.6's "warning at the first failure" — a warning nobody
 * receives is the twenty-ninth-day behaviour by another route — so this
 * resolves the administrative roles that already exist and stops there.
 *
 * 🛑 A **domain** is organisation-scoped and belongs to no project, which is
 * why this is not `ProjectOwners` with a different argument: there is no
 * project scope to union in, and inventing one would mail a project's admins
 * about a hostname their project may not even be mounted on.
 */
final class OrganisationOwners
{
    /**
     * @param  string  $organisationId  raw 16 bytes
     * @return list<User>
     */
    public static function of(string $organisationId): array
    {
        /** @var list<object{subject_id: string}> $rows */
        $rows = DB::select(
            'SELECT DISTINCT `ra`.`subject_id`
               FROM `role_assignments` AS `ra`
              WHERE `ra`.`subject_type` = ?
                AND `ra`.`role` IN (?, ?)
                AND (`ra`.`expires_at` IS NULL OR `ra`.`expires_at` > ?)
                AND (
                      (`ra`.`scope_type` = ? AND `ra`.`scope_id` IS NULL)
                   OR (`ra`.`scope_type` = ? AND `ra`.`scope_id` = ?)
                )',
            [
                'user',
                Role::OrgAdmin->value,
                Role::InstallationOwner->value,
                now(),
                'installation',
                'organisation', $organisationId,
            ],
        );

        if ($rows === []) {
            return [];
        }

        /** @var list<User> */
        return User::query()
            ->whereIn('id', array_map(static fn (object $row): string => (string) $row->subject_id, $rows))
            ->get()
            ->all();
    }
}
