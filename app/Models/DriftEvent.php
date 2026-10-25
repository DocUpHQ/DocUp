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
use Illuminate\Support\Carbon;

/**
 * 🛑 §8.8.8's second half: a composition change that has not been published.
 *
 * > "every unpublished composition change as a drift event carrying the
 * > per-mount before/after ref, commit and build id."
 *
 * The gate it feeds is §8.8.7's: `publish_mode` defaults to `manual` for
 * release-kind versions, so a selector that now resolves somewhere else
 * does not change what a shipped release serves until a human says so.
 *
 * 🛑 `auto` is a **state**, not the absence of a row, and §18.25 is why:
 * the assumption being tested is that approval-gated publication survives
 * contact with operators rather than everything becoming `auto`, and its
 * pre-decided consequence is "Keep the drift event and audit record for
 * every **automatic** publication so the evidence trail survives either
 * outcome." A table that only recorded the gated cases would make the
 * assumption unfalsifiable.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $project_version_id
 * @property string $state
 * @property array<string, mixed> $changes_json
 * @property string|null $manifest_id
 * @property string|null $decided_by
 * @property Carbon|null $decided_at
 * @property string|null $decision_reason
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
final class DriftEvent extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    protected $table = 'project_version_drift_events';

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @var array<string, mixed> */
    protected $attributes = ['state' => 'pending'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'changes_json' => 'array',
            'decided_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<ProjectVersion, $this> */
    public function projectVersion(): BelongsTo
    {
        return $this->belongsTo(ProjectVersion::class);
    }
}
