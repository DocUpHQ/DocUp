<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\AccessLevel;
use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * A unit of documentation that can be mounted into versions (§7.2, §10.2).
 *
 * Phase 03 creates exactly one per project — the degenerate case §17 names —
 * with a single primary mount at `mount_path=''`. Phase 13 adds the write-side
 * behaviour that makes components first-class. The table exists now because
 * `builds.component_id` and `manifest_builds` have no meaning without it, and
 * retrofitting the component layer under a live serving path is the
 * un-retrofittable change Phase 00 forbids.
 *
 * 🛑 `min_access` is a **ceiling** (§8.7.7), not a grant: mounting is refused
 * when a component demands more protection than the version would give it. It
 * defaults to `members` so that a component created before anyone thinks about
 * access cannot be the thing that publishes it.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $key
 * @property string|null $owner_team_id 🛑 §8.7.8; null means organisation-owned
 * @property string $name
 * @property AccessLevel $min_access
 * @property string $default_base_url_mode §8.7.11; a mount may override it
 * @property string $state
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['key', 'name', 'min_access', 'default_base_url_mode', 'collision_policy', 'suggested_mount_path'])]
final class Component extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;
    use SoftDeletes;

    /** @var array<string, mixed> */
    protected $attributes = [
        'min_access' => 'members',
        'default_base_url_mode' => 'relative',
        'collision_policy' => 'fail',
        'state' => 'active',
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'min_access' => AccessLevel::class,
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
            'deleted_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return HasMany<ComponentMount, $this> */
    public function mounts(): HasMany
    {
        return $this->hasMany(ComponentMount::class);
    }

    /** @return HasMany<Build, $this> */
    public function builds(): HasMany
    {
        return $this->hasMany(Build::class);
    }
}
