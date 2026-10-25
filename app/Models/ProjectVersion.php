<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\AccessLevel;
use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use App\Support\Uuid;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

/**
 * One version of a project — the thing a URL resolves to (§8.6, §10.4).
 *
 * 🛑 **`published_manifest_id` is a manifest, never a build** (§8.8.3), and
 * that applies "from the first phase that serves anything". A `current_build_id`
 * with a later migration to a manifest pointer is the un-retrofittable change
 * Phase 00 forbids, on the hottest path in the product — so the degenerate
 * single-component manifest exists in Phase 03 rather than being deferred until
 * composition needs it.
 *
 * 🛑 **`language` is part of the identity**, which is why §10.4 makes the unique
 * key `(project_id, language, slug)` and not `(project_id, slug)`. §8.6.12 makes
 * language a property of the version, so `/en/v2/` and `/ja/v2/` are two rows
 * that share a slug by design.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $project_id
 * @property string $slug
 * @property string $kind
 * @property string $language
 * @property bool $active
 * @property bool $listed
 * @property bool $published
 * @property AccessLevel $visibility
 * @property string $publish_mode
 * @property array<array-key, mixed>|null $layout_json §8.7.6 layout tree, per version
 * @property string|null $published_manifest_id
 * @property string|null $previous_manifest_id
 * @property Carbon|null $soft_landing_until
 * @property bool $pinned
 * @property string|null $pinned_reason
 * @property Carbon|null $pinned_at
 * @property string|null $pinned_by
 * @property string|null $ref_name
 * @property string|null $ref_kind
 * @property string|null $ref_commit_sha
 * @property Carbon|null $ref_seen_at
 * @property Carbon|null $ref_disappeared_at
 * @property Carbon|null $wiped_at
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['slug', 'kind', 'language', 'active', 'listed', 'visibility', 'publish_mode'])]
final class ProjectVersion extends Model
{
    use BelongsToOrganisation;

    /*
     * Aliased for the same reason Project aliases it: `parent::` from a class
     * resolves to the parent class, not to a flattened trait, so without the
     * alias the UUID branch would be unreachable and every lookup would fall
     * through to the slug branch — silently.
     */
    use HasUuidKey {
        resolveRouteBinding as resolveRouteBindingByUuid;
    }
    use SoftDeletes;

    /**
     * 🛑 Mirrors the column defaults so a freshly created instance agrees with
     * the row just written. `visibility` is on the §12.3 lattice and reading
     * null from it is worse than reading a restrictive value.
     *
     * @var array<string, mixed>
     */
    protected $attributes = [
        'kind' => 'channel',
        'language' => 'en',
        'active' => true,
        'listed' => true,
        'published' => false,
        'visibility' => 'restricted',
        'publish_mode' => 'auto',
        'pinned' => false,
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'active' => 'boolean',
            'layout_json' => 'array',
            'listed' => 'boolean',
            'published' => 'boolean',
            'pinned' => 'boolean',
            'visibility' => AccessLevel::class,
            'soft_landing_until' => 'datetime:Y-m-d H:i:s.v',
            'ref_seen_at' => 'datetime:Y-m-d H:i:s.v',
            'ref_disappeared_at' => 'datetime:Y-m-d H:i:s.v',
            'wiped_at' => 'datetime:Y-m-d H:i:s.v',
            'pinned_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
            'deleted_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<Project, $this> */
    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class);
    }

    /** @return BelongsTo<ProjectVersionManifest, $this> */
    public function publishedManifest(): BelongsTo
    {
        return $this->belongsTo(ProjectVersionManifest::class, 'published_manifest_id');
    }

    /** @return BelongsTo<ProjectVersionManifest, $this> */
    public function previousManifest(): BelongsTo
    {
        return $this->belongsTo(ProjectVersionManifest::class, 'previous_manifest_id');
    }

    /** @return HasMany<ComponentMount, $this> */
    public function mounts(): HasMany
    {
        return $this->hasMany(ComponentMount::class);
    }

    /** @return HasMany<ProjectVersionManifest, $this> */
    public function manifests(): HasMany
    {
        return $this->hasMany(ProjectVersionManifest::class);
    }

    /** @return HasMany<VersionPointerEvent, $this> */
    public function pointerEvents(): HasMany
    {
        return $this->hasMany(VersionPointerEvent::class);
    }

    /**
     * Find a version by a project reference and a version reference.
     *
     * 🛑 One lookup for both, so that §8.2.2's "404, never 403" has a single
     * answer. Route-model binding would need two bindings plus a relationship
     * check, which is three places for one of them to answer differently — and
     * the cases that must be indistinguishable are: wrong tenant, no such
     * project, no such version, and a version belonging to a different project.
     *
     * Both references accept a slug or a canonical UUID, because §8.2.2 names
     * "direct identifier access" as the third route that must also 404. It is
     * safe for the same reason the whole requirement works: resolution runs
     * through the §8.2.1 global scope, so knowing a key does not help.
     */
    public static function locate(string $projectReference, string $versionReference): ?self
    {
        $project = (new Project)->resolveRouteBinding($projectReference);

        if (! $project instanceof Project) {
            return null;
        }

        $version = self::query()
            ->where('project_id', $project->id)
            ->where(function (Builder $query) use ($versionReference): void {
                $query->where('slug', $versionReference);

                /*
                 * The identifier form is added only when the value really is a
                 * UUID. `Uuid::toBytes()` throws on anything else by design
                 * (ADR 0006 prefers a loud failure at a conversion boundary),
                 * so this guard is what keeps a slug like `latest` a 404 rather
                 * than a 500.
                 */
                if (Str::isUuid($versionReference)) {
                    $query->orWhere('id', Uuid::toBytes($versionReference));
                }
            })
            // §10.4's unique key is (project_id, language, slug), so a slug
            // alone is ambiguous across languages. Ordered rather than
            // arbitrary; a language-qualified route is §8.6's business and
            // arrives with the resolver in Phase 04.
            ->orderBy('language')
            ->first();

        return $version instanceof self ? $version : null;
    }

    /**
     * The default `publish_mode` for a version of this kind (§8.8.7).
     *
     * `auto` for a channel, `manual` for a release. A channel such as `latest`
     * tracks a branch and is expected to move on its own; a release is a thing
     * somebody decided to ship, and having it republish itself because a commit
     * landed on the tag is the opposite of what shipping means.
     */
    public static function defaultPublishModeFor(string $kind): string
    {
        return $kind === 'release' ? 'manual' : 'auto';
    }

    /**
     * Whether the previous manifest is still inside its soft-landing window
     * (§8.8.6).
     *
     * 🛑 The window is what stops every publish breaking every page currently
     * open. A page delivered a second before the flip holds relative asset URLs
     * that resolve against the old build's prefix, and without this the next
     * request for one of them is a 404 in a reader's browser — a self-inflicted
     * outage on every successful publish.
     */
    public function isWithinSoftLanding(): bool
    {
        return $this->previous_manifest_id !== null
            && $this->soft_landing_until !== null
            && $this->soft_landing_until->isFuture();
    }

    /**
     * Whether an automatic publish is currently blocked (§8.8.5).
     *
     * 🛑 A pin blocks **automatic** republication only. A human with the
     * capability can still publish deliberately — the pin records a decision,
     * it is not a lock — but the next successful build must not quietly
     * republish the thing somebody just rolled back. That would be the worst
     * available response to someone deciding a release was bad.
     */
    public function blocksAutomaticPublish(): bool
    {
        return $this->pinned || $this->publish_mode === 'manual';
    }

    /**
     * Resolve a route parameter by slug **or** by UUID.
     *
     * 🛑 §8.2.2 wants "the UI, the API **and** direct identifier access" all to
     * answer 404 for another tenant's row, and accepting both forms on one
     * route is what makes that testable with one endpoint. It is safe for the
     * same reason the requirement works at all: resolution runs through the
     * §8.2.1 global scope, so neither form reaches outside the declared tenant.
     *
     * @param  mixed  $field  `mixed` for contravariance with UrlRoutable
     */
    public function resolveRouteBinding(mixed $value, mixed $field = null): ?Model
    {
        if (! is_string($value) || $value === '') {
            return null;
        }

        $byUuid = $this->resolveRouteBindingByUuid($value, $field);

        if ($byUuid !== null) {
            return $byUuid;
        }

        /*
         * Slug alone is ambiguous across languages — `(project_id, language,
         * slug)` is the unique key — so this returns the first match in a
         * stable order rather than pretending the lookup is exact. A
         * language-qualified route is §8.6's business and arrives with the
         * resolver in Phase 04; until something serves URLs, the only callers
         * are the publish API, which addresses a version it just created or was
         * given the id of.
         */
        return self::query()
            ->where('slug', $value)
            ->orderBy('language')
            ->first();
    }
}
