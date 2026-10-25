<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Composition\ResolutionOutcome;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * 🛑 §8.8.8's append-only record of one selector resolution.
 *
 * > "Every selector resolution MUST be recorded as an append-only row"
 *
 * Written on every publish, for every mount, whether or not the answer
 * changed — because the question "what did this mount resolve to on
 * 4 March" cannot be answered from a table that only records changes
 * without also knowing when nothing was recorded and why.
 *
 * The selector's own configuration is **copied** rather than joined. A
 * record of a decision that reads today's configuration is a record of
 * nothing: a mount edited from `track_branch` to `pinned_build` would
 * rewrite every historical row's apparent reasoning.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $project_version_id
 * @property string $component_mount_id
 * @property string $component_id
 * @property string $selector_kind
 * @property string|null $selector_value
 * @property string|null $mirror_fallback
 * @property string|null $resolved_label
 * @property string|null $resolved_ref
 * @property string|null $resolved_commit_sha
 * @property string|null $build_id
 * @property ResolutionOutcome $outcome
 * @property string|null $manifest_id
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
final class MountResolution extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** Append-only: a resolution that already happened has no later state. */
    public const UPDATED_AT = null;

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'outcome' => ResolutionOutcome::class,
            'created_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<ProjectVersion, $this> */
    public function projectVersion(): BelongsTo
    {
        return $this->belongsTo(ProjectVersion::class);
    }

    /** @return BelongsTo<ComponentMount, $this> */
    public function componentMount(): BelongsTo
    {
        return $this->belongsTo(ComponentMount::class);
    }
}
