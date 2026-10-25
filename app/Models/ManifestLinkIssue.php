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
 * 🛑 §8.7.16's recorded, non-fatal cross-reference failure.
 *
 * > "Unresolved references MUST be recorded as publish-time link issues that
 * > **never fail a build and never block a publish** — one repository's typo
 * > must not break another repository's build."
 *
 * Scoped to the **manifest** rather than to the build, because whether a
 * cross-component reference resolves is a property of the composition. The
 * same build mounted beside the glossary has no issue; mounted without it,
 * it has one. A build-scoped row would be wrong for one of those projects
 * and would make one team's publish able to mark another team's build
 * defective.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $manifest_id
 * @property string $component_id
 * @property string $source_path
 * @property string $target_component_key
 * @property string $target_path
 * @property string $kind
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
final class ManifestLinkIssue extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** Written once, at publish, for a manifest that is itself immutable. */
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
}
