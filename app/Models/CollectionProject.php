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
 * One project's membership of one collection, under one alias (§10.1).
 *
 * 🛑 The alias lives here and not on `projects`, because the same project is
 * a member of two collections under two different aliases — which is the
 * same argument §8.7.1 makes for component identity being repository-
 * independent, applied one level up.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $collection_id
 * @property string $project_id
 * @property string $alias §8.21.2's subproject URL segment
 * @property string|null $domain_mount_id the hosting row this produced, if any
 * @property int $position
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['alias', 'position'])]
final class CollectionProject extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'position' => 0,
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'position' => 'integer',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<Collection, $this> */
    public function collection(): BelongsTo
    {
        return $this->belongsTo(Collection::class);
    }

    /** @return BelongsTo<Project, $this> */
    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class);
    }
}
