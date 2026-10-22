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
 * One append-only record of a serving-pointer flip (§8.8.8, §10.4).
 *
 * §8.8.8: "Every selector resolution MUST be recorded as an append-only row."
 * This is the version-level half of that — what the version served before and
 * after, and why.
 *
 * 🛑 Both the manifest ids and the build ids are stored. The manifest ids are
 * what actually flipped (§8.8.3); the build ids are what §10.4 names and what a
 * human reading an incident timeline recognises. In Phase 03's degenerate
 * single-component case there is one build per manifest so the two agree; once a
 * manifest spans several components they diverge, and the manifest columns are
 * the ones that still mean something. The proposed amendment is recorded in the
 * migration that creates this table.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $project_version_id
 * @property string|null $from_manifest_id
 * @property string|null $to_manifest_id
 * @property string|null $from_build_id
 * @property string|null $to_build_id
 * @property string $reason
 * @property string|null $actor_id
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
final class VersionPointerEvent extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** Append-only: there is no later state for an event that already happened. */
    public const UPDATED_AT = null;

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['created_at' => 'datetime:Y-m-d H:i:s.v'];
    }

    /** @return BelongsTo<ProjectVersion, $this> */
    public function projectVersion(): BelongsTo
    {
        return $this->belongsTo(ProjectVersion::class);
    }
}
