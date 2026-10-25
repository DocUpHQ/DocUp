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
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * §8.7.8: one team's permission to mount one component.
 *
 * > "Mounting a component a team does not own MUST require an explicit
 * > `component_grants` row. Mounting is not implicitly organisation-wide."
 *
 * 🛑 The grantee is a TEAM, not a user. §8.2 models permission through
 * teams, and a grant to a person is a grant that leaves with them — the
 * component stays mounted and the permission that allowed it is gone, so
 * nobody can say afterwards whether the mount was ever authorised.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $component_id
 * @property string $team_id
 * @property string $capability
 * @property string|null $granted_by
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['capability'])]
final class ComponentGrant extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @var array<string, mixed> */
    protected $attributes = ['capability' => 'mount'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<Component, $this> */
    public function component(): BelongsTo
    {
        return $this->belongsTo(Component::class);
    }

    /** @return BelongsTo<Team, $this> */
    public function team(): BelongsTo
    {
        return $this->belongsTo(Team::class);
    }
}
