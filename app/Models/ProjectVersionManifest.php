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
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * The immutable composition a version serves (§8.8.3, §10.4).
 *
 * 🛑 **Immutable** is enforced here, not merely documented. Nothing updates a
 * manifest row: a change means a new revision. That is what lets §8.8.6's
 * soft-landing window work — the previous manifest is still exactly what the
 * already-delivered HTML expects — and what makes rollback a pointer flip
 * rather than a rebuild. A manifest that could be edited in place would make
 * both of those silently wrong: the bytes a reader's browser is about to ask
 * for would have moved, and the thing rollback returned to would not be the
 * thing that was previously served.
 *
 * Phase 03 writes the degenerate case §17 names: one component, one primary
 * mount at `mount_path=''`. The shape is the real one from the start, because
 * §8.8.3 applies "from the first phase that serves anything" and a later move
 * from a build pointer to a manifest pointer is the un-retrofittable change
 * Phase 00 forbids.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $project_version_id
 * @property int $revision
 * @property array<string, mixed> $mounts_json
 * @property array<string, mixed>|null $nav_json
 * @property array<string, mixed>|null $xref_json
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
final class ProjectVersionManifest extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** No `updated_at`: a manifest that changed would not be a manifest. */
    public const UPDATED_AT = null;

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'revision' => 'integer',
            'mounts_json' => 'array',
            'nav_json' => 'array',
            'xref_json' => 'array',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /**
     * 🛑 Refuse to persist a change to a row that already exists.
     *
     * Documentation is not a control. §8.8.6 and §8.8.5 both rest on a stored
     * manifest never changing, and an `update()` somewhere in a later phase
     * would break them without failing anything — the pointer would still
     * resolve, the composition would just have quietly become something else.
     *
     * A model event rather than a database trigger because the audit tables'
     * triggers taught us the cost: `CREATE TRIGGER` needs SUPER, which turns an
     * invariant into an operator deployment step. This one is reachable only
     * through Eloquent, and the architecture tests keep raw manifest writes out
     * of the tree.
     */
    protected static function booted(): void
    {
        self::updating(static function (self $manifest): void {
            throw new \LogicException(
                'A project version manifest is immutable (§10.4). Create a new revision instead of updating '
                .'revision '.$manifest->revision.'; §8.8.6 and §8.8.5 both depend on a stored manifest never '
                .'changing.'
            );
        });

        self::deleting(static function (self $manifest): void {
            /*
             * Deleting one is as bad as editing it. §8.8.5 requires the
             * previous build to stay "intact and immediately re-selectable",
             * and §8.8.9 routes artifact removal through a quarantine with a
             * 14-day grace rather than deleting outright — a manifest row
             * deleted while its artifacts survive leaves bytes nothing can
             * reach, which is the worst of both.
             */
            throw new \LogicException(
                'A project version manifest is immutable (§10.4) and is never deleted; revision '
                .$manifest->revision.' must stay re-selectable for rollback (§8.8.5).'
            );
        });
    }

    /** @return BelongsTo<ProjectVersion, $this> */
    public function projectVersion(): BelongsTo
    {
        return $this->belongsTo(ProjectVersion::class);
    }

    /** @return HasMany<ManifestBuild, $this> */
    public function manifestBuilds(): HasMany
    {
        return $this->hasMany(ManifestBuild::class, 'manifest_id');
    }

    /**
     * The build serving a given mount path, from the stored composition.
     *
     * Read from `mounts_json` rather than by joining `manifest_builds`, because
     * §8.4.18 requires the serving path to answer without a query per request
     * and §18.8 is the (still unverified) assumption that this column is fast
     * enough for it. Phase 04 owns that benchmark; nothing here is on a hot path
     * yet, which is why the assumption is not load-bearing today.
     */
    public function buildIdForMount(string $mountPath): ?string
    {
        /** @var array<array-key, mixed> $mounts */
        $mounts = $this->mounts_json['mounts'] ?? [];

        foreach ($mounts as $mount) {
            if (! is_array($mount)) {
                continue;
            }

            if (($mount['mount_path'] ?? null) !== $mountPath) {
                continue;
            }

            $buildId = $mount['build_id'] ?? null;

            return is_string($buildId) ? $buildId : null;
        }

        return null;
    }
}
