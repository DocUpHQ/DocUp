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
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * One component mounted into one version at one path (§8.7, §10.2).
 *
 * 🛑 `mount_path_hash` and `primary_marker` are STORED generated columns and the
 * application never writes them. `mount_path_hash` is what the unique index is
 * over (§9.1.5), because a 255-byte utf8mb4 column is 1,020 bytes and combined
 * with the version key approaches InnoDB's index limit; `primary_marker` is the
 * §18.21 idiom that makes "at most one primary mount per version" a database
 * constraint rather than application code with a race window. Both are listed in
 * `$guarded` to make an accidental write fail loudly rather than be silently
 * dropped by MySQL.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $project_version_id
 * @property string $component_id
 * @property string $mount_path
 * @property bool $is_primary
 * @property AccessLevel $min_access_snapshot
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['mount_path', 'selector_kind', 'selector_value', 'is_required', 'is_primary', 'min_access_snapshot'])]
final class ComponentMount extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /**
     * @var list<string>
     *
     * The two generated columns. MySQL rejects an INSERT that names a STORED
     * generated column, so without this an attempt to set one would surface as
     * a query error rather than as the programming mistake it is.
     */
    protected $guarded = ['id', 'mount_path_hash', 'primary_marker'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'mount_path' => '',
        'selector_kind' => 'latest_success',
        'is_required' => true,
        'is_primary' => false,
        'min_access_snapshot' => 'members',
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'is_required' => 'boolean',
            'is_primary' => 'boolean',
            'min_access_snapshot' => AccessLevel::class,
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<Component, $this> */
    public function component(): BelongsTo
    {
        return $this->belongsTo(Component::class);
    }

    /** @return BelongsTo<ProjectVersion, $this> */
    public function projectVersion(): BelongsTo
    {
        return $this->belongsTo(ProjectVersion::class);
    }
}
