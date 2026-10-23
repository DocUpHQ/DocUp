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
 * One contributing source, pinned (§8.5.1).
 *
 * > "every contributing ref pinned to an immutable commit SHA by
 * > `git ls-remote` **before any repository code executes**, with the resolved
 * > plan recorded immutably on the build record"
 *
 * 🛑 `filter_honoured` is ADR 0010's requirement and §18.14's "recorded
 * 'filter honoured' flag per provider". The failure it catches is silent: a
 * server that does not support partial clone completes the clone perfectly
 * and says nothing. Without this column the only symptom is fetches getting
 * slower, which nobody attributes to a protocol negotiation.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $build_id
 * @property string|null $component_source_id
 * @property string $repository_id
 * @property string $ref
 * @property string $commit_sha
 * @property string $source_path
 * @property bool|null $filter_honoured
 * @property string|null $partial_clone_filter
 * @property bool|null $shallow
 * @property int|null $worktree_files
 * @property int|null $fetched_bytes
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
final class BuildSource extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @var array<string, mixed> */
    protected $attributes = [
        'source_path' => '',
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'filter_honoured' => 'boolean',
            'shallow' => 'boolean',
            'worktree_files' => 'integer',
            'fetched_bytes' => 'integer',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<Build, $this> */
    public function build(): BelongsTo
    {
        return $this->belongsTo(Build::class);
    }

    /** @return BelongsTo<Repository, $this> */
    public function repository(): BelongsTo
    {
        return $this->belongsTo(Repository::class);
    }

    /** @return BelongsTo<ComponentSource, $this> */
    public function componentSource(): BelongsTo
    {
        return $this->belongsTo(ComponentSource::class);
    }
}
