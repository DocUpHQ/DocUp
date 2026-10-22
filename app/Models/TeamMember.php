<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;

/**
 * Membership of a team (§8.2.3).
 *
 * 🛑 §12.1: membership, not permission. Roles resolve through
 * `role_assignments`; a team is a way to name a set of people. There is
 * deliberately no role column.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $team_id
 * @property string $user_id
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['team_id', 'user_id'])]
final class TeamMember extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }
}
