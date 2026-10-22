<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * Which build of which component a manifest resolved to (§10.4).
 *
 * One row per component per manifest, enforced by a unique index: a manifest
 * naming two builds for one component would have no defined resolution, and the
 * serving path would have to pick — silently, differently per request.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $manifest_id
 * @property string $component_id
 * @property string $build_id
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
final class ManifestBuild extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /**
     * No `updated_at`: this is a row in an immutable manifest's membership
     * list. A manifest never changes, so neither does its membership.
     */
    public const UPDATED_AT = null;

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['created_at' => 'datetime:Y-m-d H:i:s.v'];
    }

    /** @return BelongsTo<ProjectVersionManifest, $this> */
    public function manifest(): BelongsTo
    {
        return $this->belongsTo(ProjectVersionManifest::class, 'manifest_id');
    }

    /** @return BelongsTo<Build, $this> */
    public function build(): BelongsTo
    {
        return $this->belongsTo(Build::class);
    }
}
