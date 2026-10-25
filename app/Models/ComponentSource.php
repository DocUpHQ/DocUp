<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Composition\SourceDirtiness;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * Where a component's identity currently lives (§10.2).
 *
 * 🛑 The indirection is the composition model. A component is an org-scoped,
 * **repository-independent** identity; this row says which repository and
 * which path inside it currently produce that component's documentation. One
 * repository carrying three sources is a monorepo contributing three
 * components; one component whose source moves to a new repository keeps its
 * key, its mounts and its history. Collapsing the two would make both cases
 * a migration.
 *
 * Created in Phase 05 rather than Phase 13 because it carries the foreign key
 * to `repositories` — §10.2 says exactly that, and names it as the reason the
 * table was absent from Phase 03.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $component_id
 * @property string $repository_id
 * @property string $source_path
 * @property string $module
 * @property int $priority
 * @property string $state
 *
 * 🛑 `path_filters` is typed as untrusted rather than as `list<string>`,
 * and deliberately: it is operator-supplied JSON reaching us through
 * §8.19.1's API, so its contents are whatever was written. The runtime
 * checks in {@see SourceDirtiness::globsFor()} are the
 * ones that matter, and a tighter annotation here would tell the analyser
 * to stop checking them.
 * @property array<array-key, mixed>|null $path_filters
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['source_path', 'module', 'priority', 'path_filters', 'ref_include_patterns', 'ref_exclude_patterns'])]
final class ComponentSource extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;
    use SoftDeletes;

    /** @var array<string, mixed> */
    protected $attributes = [
        'source_path' => '',
        'module' => '',
        'priority' => 100,
        'version_label_strategy' => 'ref_name',
        'state' => 'active',
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'path_filters' => 'array',
            'ref_include_patterns' => 'array',
            'ref_exclude_patterns' => 'array',
            'priority' => 'integer',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
            'deleted_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<Component, $this> */
    public function component(): BelongsTo
    {
        return $this->belongsTo(Component::class);
    }

    /** @return BelongsTo<Repository, $this> */
    public function repository(): BelongsTo
    {
        return $this->belongsTo(Repository::class);
    }
}
