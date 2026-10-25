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
 * Where a project is served on a hostname (§8.10.1, §10.5).
 *
 * The table has existed since Phase 04, which created it with its full column
 * set and nothing that wrote to it but a test fixture — the serving path reads
 * it through {@see App\Serving\RoutingSnapshotLoader} and never through
 * Eloquent, because §8.9.1 requires the resolver to take a pre-loaded snapshot.
 * This model is the **write** side, and it arrives with §8.2.6's collections
 * because a collection member is a `domain_mounts` row: "Every hosting shape —
 * … path-prefix portal, collection grouping and preview host — MUST be a
 * `domain_mounts` row keyed `(domain_id, path_prefix)`."
 *
 * Domain claiming, verification and the rest of §8.10 are Phase 18's and
 * Phase 19's. Mounting a project on a domain that already exists is not that,
 * and the two are kept apart deliberately: nothing here creates or verifies a
 * `domains` row.
 *
 * 🛑 `canonical_for_project_id` and `is_indexable` are generated columns and
 * the application never writes them — MySQL rejects an INSERT naming a STORED
 * generated column, so `$guarded` makes an attempt fail as the programming
 * mistake it is rather than as a query error.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $domain_id
 * @property string $project_id
 * @property string $path_prefix '' at the host root
 * @property string $mode §8.10.2; canonical, serve or redirect
 * @property string $mount_exposure 🛑 §12.3's lattice plus `inherit`; narrowing only
 * @property-read bool $is_indexable derived from `mode = 'canonical'`
 * @property int $position
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['path_prefix', 'mode', 'mount_exposure', 'position'])]
final class DomainMount extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @var list<string> */
    protected $guarded = ['id', 'canonical_for_project_id', 'is_indexable'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'path_prefix' => '',
        'mode' => 'serve',
        'mount_exposure' => 'inherit',
        'position' => 0,
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'is_indexable' => 'boolean',
            'position' => 'integer',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<Project, $this> */
    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class);
    }
}
