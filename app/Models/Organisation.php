<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * The tenancy boundary itself (§8.2.1).
 *
 * `final` for the reason given on {@see User}: DocUp has no single-table
 * inheritance anywhere in §10.
 *
 * @property-read string $id
 * @property string $name
 * @property string $slug
 * @property string $default_timezone
 */
#[Tenancy(
    TenancyPosture::Installation,
    because: 'This table IS the tenancy root. Its `id` is the organisation id, so there is no '
        .'`organisation_id` to filter on and BelongsToOrganisation cannot apply. Which '
        .'organisations a person may see is decided by their role assignments, not by the '
        .'global scope — and deliberately so: the installation owner must be able to '
        .'enumerate every tenant.'
)]
#[Fillable(['name', 'slug', 'default_timezone'])]
final class Organisation extends Model
{
    use HasUuidKey;
    use SoftDeletes;

    /**
     * 🛑 §8.22.13: UTC `DATETIME(3)`, never `TIMESTAMP`.
     *
     * Declared because Laravel's default `datetime` cast drops the
     * milliseconds the column stores, and an audit trail that rounds its own
     * timestamps cannot order two events in the same second.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
            'deleted_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return HasMany<Project, $this> */
    public function projects(): HasMany
    {
        return $this->hasMany(Project::class);
    }

    /** @return HasMany<Team, $this> */
    public function teams(): HasMany
    {
        return $this->hasMany(Team::class);
    }
}
