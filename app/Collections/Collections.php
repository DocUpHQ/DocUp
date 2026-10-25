<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Collections;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Models\Collection;
use App\Models\CollectionProject;
use App\Models\DomainMount;
use App\Models\Project;
use App\Support\Uuid;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;

/**
 * The write side of §8.2.5's collections.
 *
 * 🛑 **Attaching a member materialises a `domain_mounts` row, and that is the
 * whole design.** §8.10.1 already names "collection grouping" as one of the
 * seven hosting shapes that MUST be a `domain_mounts` row, and §17.4 froze
 * §7.3's grammar at the end of Phase 04 — so a collection cannot be a step in
 * the grammar. It is a *management* construct over rows the resolver already
 * understands, which is why Phase 16 adds no line to {@see App\Serving\Resolver}.
 *
 * The checks here are the ones an index cannot express: that an alias is a
 * usable path segment (§8.2.6), that it does not collide with a version slug
 * of the parent (§8.6.6's rule, read from the other end), and 🛑 that the
 * mount does not widen access (§8.12.8). The unique indexes are still the
 * arbiter for the rest — two concurrent attaches both pass the checks and one
 * loses on the insert, and the violation is re-reported as the same
 * identifier so a caller sees one answer whichever way it was caught.
 */
final readonly class Collections
{
    /**
     * Create a collection.
     *
     * @param  string|null  $actorId  raw 16 bytes, or null when the system did it
     *
     * @throws CollectionRefused
     */
    public function create(
        string $organisationId,
        string $slug,
        string $name,
        ?Project $parent = null,
        string $prefixConvention = 'projects',
        ?string $actorId = null,
    ): Collection {
        /*
         * The collection's own slug occupies the same kind of position an
         * alias does, so it answers to the same refusals — and always under
         * the stricter reading, because a slug is an operator-facing name
         * rather than a URL the importer has to preserve.
         */
        CollectionAlias::assertUsable($slug, 'alias');

        if ($parent instanceof Project && $parent->organisation_id !== $organisationId) {
            throw CollectionRefused::of(CollectionRejection::CrossTenant, $parent->slug);
        }

        $collection = new Collection;

        try {
            $collection->forceFill([
                'id' => Uuid::v7(),
                'organisation_id' => $organisationId,
                'parent_project_id' => $parent?->id,
                'slug' => $slug,
                'name' => $name,
                'prefix_convention' => $prefixConvention,
            ])->save();
        } catch (UniqueConstraintViolationException) {
            throw CollectionRefused::of(CollectionRejection::AliasTaken, $slug);
        }

        Audit::record(
            action: 'collection.created',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $organisationId,
            actorId: $actorId,
            subjectType: 'collection',
            subjectId: $collection->id,
            payload: [
                'slug' => $slug,
                'parent' => $parent === null ? null : $parent->slug,
                'prefix_convention' => $prefixConvention,
            ],
        );

        return $collection;
    }

    /**
     * Attach a project to a collection, mounting it under the parent's domain.
     *
     * @param  string  $mountExposure  🛑 §12.3's lattice plus `inherit`; narrowing only
     * @param  string|null  $actorId  raw 16 bytes, or null when the system did it
     *
     * @throws CollectionRefused
     */
    public function attach(
        Collection $collection,
        Project $project,
        string $alias,
        string $mountExposure = 'inherit',
        int $position = 0,
        ?string $actorId = null,
    ): CollectionProject {
        CollectionAlias::assertUsable($alias, $collection->prefix_convention);

        if ($project->organisation_id !== $collection->organisation_id) {
            throw CollectionRefused::of(CollectionRejection::CrossTenant, $project->slug);
        }

        /*
         * 🛑 §4.2's "nested collections are out of scope", at the only depth
         * it can be violated with two tables: the parent is where the
         * collection's prefix comes from, so a parent that is also a member
         * would be mounted underneath itself.
         */
        if ($collection->parent_project_id === $project->id) {
            throw CollectionRefused::of(CollectionRejection::ParentCannotBeMember, $project->slug);
        }

        $parentMount = $this->parentMountOf($collection);

        $prefix = $this->prefixFor($collection, $parentMount, $alias);

        $this->assertNoVersionCollision($collection, $alias, $prefix, $parentMount);

        // 🛑 §8.12.8, before anything is written. A widening exposure is
        // refused at write time or it is not refused at all.
        MountExposure::assertNarrows($mountExposure, $project->visibility);

        return DB::transaction(function () use (
            $collection, $project, $alias, $prefix, $parentMount, $mountExposure, $position, $actorId
        ): CollectionProject {
            /*
             * 🛑 The membership first, then the mount, and the order is what
             * the operator hears. Both rows have a unique index that this
             * attach can violate — `(collection_id, alias)` and
             * `(domain_id, path_prefix)` — and the prefix is *derived* from
             * the alias, so a duplicate alias violates both. Mounting first
             * reported `collection.prefix_taken` for an alias somebody had
             * simply used twice, which names a column they never typed.
             */
            $membership = new CollectionProject;

            try {
                $membership->forceFill([
                    'id' => Uuid::v7(),
                    'organisation_id' => $collection->organisation_id,
                    'collection_id' => $collection->id,
                    'project_id' => $project->id,
                    'alias' => $alias,
                    'position' => $position,
                ])->save();
            } catch (UniqueConstraintViolationException $collision) {
                /*
                 * 🛑 Matched on the INDEX name, not on the word `alias`. The
                 * exception message carries the whole INSERT, whose column
                 * list names `alias` on every violation — so a looser match
                 * reported `collection.alias_taken` for a project joining
                 * the same collection twice, and told an operator to rename
                 * an alias that was not the problem. Caught by the test that
                 * asserts the two refusals are told apart.
                 */
                throw CollectionRefused::of(
                    str_contains($collision->getMessage(), 'collection_projects_alias_unique')
                        ? CollectionRejection::AliasTaken
                        : CollectionRejection::AlreadyMember,
                    'refused by the database index',
                );
            }

            $mount = $this->mountMember($collection, $project, $parentMount, $prefix, $mountExposure, $position);

            $membership->forceFill(['domain_mount_id' => $mount->id])->save();

            Audit::record(
                action: 'collection.member_attached',
                actorType: $actorId === null ? ActorType::System : ActorType::User,
                organisationId: $collection->organisation_id,
                actorId: $actorId,
                subjectType: 'collection_project',
                subjectId: $membership->id,
                payload: [
                    'collection' => $collection->slug,
                    'project' => $project->slug,
                    'alias' => $alias,
                    'path_prefix' => $prefix,
                    // 🛑 Recorded because it is the §8.12.8 decision. An
                    // exposure that narrows is still a change to who may read
                    // a project through this URL.
                    'mount_exposure' => $mountExposure,
                ],
            );

            return $membership;
        });
    }

    /**
     * 🛑 Switch §8.2.6's prefix convention, re-validating every alias first.
     *
     * The switch is where a safe alias becomes an ambiguous one — `api` is
     * unambiguous at `/projects/api/` and indistinguishable from a language
     * code at `/api/` — and it is also the moment nobody is looking at
     * aliases. So the whole set is re-checked under the new convention and
     * the switch is refused if any of them would no longer be usable, rather
     * than silently producing a collection some of whose members are
     * unreachable.
     *
     * Every member's mount is rewritten, because the prefix is derived from
     * the convention and a mount left at the old path is a URL the operator
     * believes they have moved.
     *
     * @throws CollectionRefused
     */
    public function changeConvention(Collection $collection, string $convention, ?string $actorId = null): void
    {
        if ($collection->prefix_convention === $convention) {
            return;
        }

        /** @var list<CollectionProject> $members */
        $members = array_values(
            CollectionProject::query()->where('collection_id', $collection->id)->get()->all(),
        );

        foreach ($members as $member) {
            CollectionAlias::assertUsable($member->alias, $convention);
        }

        $parentMount = $this->parentMountOf($collection);

        DB::transaction(function () use ($collection, $convention, $members, $parentMount, $actorId): void {
            $collection->forceFill(['prefix_convention' => $convention])->save();

            foreach ($members as $member) {
                $prefix = $this->prefixFor($collection, $parentMount, $member->alias);

                $this->assertNoVersionCollision($collection, $member->alias, $prefix, $parentMount);

                if (! is_string($member->domain_mount_id)) {
                    continue;
                }

                try {
                    DomainMount::query()
                        ->whereKey($member->domain_mount_id)
                        ->update(['path_prefix' => $prefix, 'updated_at' => now()]);
                } catch (UniqueConstraintViolationException) {
                    throw CollectionRefused::of(CollectionRejection::PrefixTaken, $prefix);
                }
            }

            Audit::record(
                action: 'collection.convention_changed',
                actorType: $actorId === null ? ActorType::System : ActorType::User,
                organisationId: $collection->organisation_id,
                actorId: $actorId,
                subjectType: 'collection',
                subjectId: $collection->id,
                payload: ['prefix_convention' => $convention, 'members' => count($members)],
            );
        });
    }

    /**
     * Detach a member, removing the mount it produced.
     *
     * The mount goes with it: §8.2.6 makes the member's URL a property of the
     * membership, so leaving the row behind would keep serving a project at a
     * collection prefix it is no longer part of — which is the one outcome an
     * operator detaching it is trying to prevent.
     */
    public function detach(CollectionProject $membership, ?string $actorId = null): void
    {
        DB::transaction(function () use ($membership, $actorId): void {
            if (is_string($membership->domain_mount_id)) {
                DomainMount::query()->whereKey($membership->domain_mount_id)->delete();
            }

            Audit::record(
                action: 'collection.member_detached',
                actorType: $actorId === null ? ActorType::System : ActorType::User,
                organisationId: $membership->organisation_id,
                actorId: $actorId,
                subjectType: 'collection_project',
                subjectId: $membership->id,
                payload: ['alias' => $membership->alias],
            );

            $membership->delete();
        });
    }

    /**
     * The parent project's mount: the domain and prefix a member hangs under.
     *
     * The **canonical** one (§8.10.3's one-per-project row), because that is
     * the mount §8.11.9 already points `rel=canonical` at — a member mounted
     * under a serving alias would be `noindex` by derivation while the parent
     * beside it was not, which is a split no operator asked for.
     *
     * @throws CollectionRefused
     */
    private function parentMountOf(Collection $collection): DomainMount
    {
        if (! is_string($collection->parent_project_id)) {
            throw CollectionRefused::of(CollectionRejection::ParentMissing, $collection->slug);
        }

        $mount = DomainMount::query()
            ->where('project_id', $collection->parent_project_id)
            ->where('mode', 'canonical')
            ->first();

        if (! $mount instanceof DomainMount) {
            throw CollectionRefused::of(CollectionRejection::ParentNotMounted, $collection->slug);
        }

        return $mount;
    }

    /** `<parent prefix>/<convention…>/<alias>`, with no empty segments. */
    private function prefixFor(Collection $collection, DomainMount $parentMount, string $alias): string
    {
        $segments = array_merge(
            $parentMount->path_prefix === '' ? [] : explode('/', $parentMount->path_prefix),
            $collection->prefixSegments(),
            [$alias],
        );

        return implode('/', $segments);
    }

    /**
     * 🛑 The two version-slug collisions, which are different (§8.6.6).
     *
     * The first is on the **alias**: §8.2.6 makes the convention a column, so
     * an alias that is only safe under `projects` becomes a live collision
     * the moment an operator switches to `alias` — and at that moment the
     * member's URLs and one of the parent's versions are the same path. It is
     * refused up front rather than at the switch, because the switch is the
     * one time nobody is looking at aliases.
     *
     * The second is on the **first segment of the computed prefix**, which
     * under the default convention is the literal `projects`. A parent with a
     * version slugged `projects` has `/projects/` as a version root, and the
     * resolver matches domain mounts longest-first — so `projects/<alias>`
     * would swallow a path inside that version, and the version would lose
     * exactly one subtree with no error anywhere.
     *
     * @throws CollectionRefused
     */
    private function assertNoVersionCollision(
        Collection $collection,
        string $alias,
        string $prefix,
        DomainMount $parentMount,
    ): void {
        $slugs = $this->versionSlugsOf((string) $collection->parent_project_id);

        if (in_array($alias, $slugs, true)) {
            throw CollectionRefused::of(CollectionRejection::AliasCollidesWithVersion, $alias);
        }

        $within = $parentMount->path_prefix === ''
            ? $prefix
            : substr($prefix, strlen($parentMount->path_prefix) + 1);

        $first = explode('/', $within)[0];

        if ($first !== $alias && in_array($first, $slugs, true)) {
            throw CollectionRefused::of(CollectionRejection::PrefixShadowsVersion, $first);
        }
    }

    /**
     * Every version slug of a project, in every language.
     *
     * Every language, because §8.6.9's `multi_version` scheme puts the slug in
     * the first segment with no language in front of it — so a slug that only
     * exists in Japanese still occupies the position an alias would take if
     * the project's scheme ever changed.
     *
     * @param  string  $projectId  raw 16 bytes
     * @return list<string>
     */
    private function versionSlugsOf(string $projectId): array
    {
        $slugs = [];

        foreach (DB::table('project_versions')
            ->where('project_id', $projectId)
            ->whereNull('deleted_at')
            ->distinct()
            ->pluck('slug')
            ->all() as $slug) {
            if (is_string($slug)) {
                $slugs[] = $slug;
            }
        }

        return $slugs;
    }

    /**
     * The member's `domain_mounts` row.
     *
     * 🛑 §8.10.2: "The **first** domain mount created for a project … MUST be
     * created with `mode='canonical'`." A member that has never been mounted
     * anywhere gets `canonical` here, so `is_indexable` — which §8.10.2
     * derives from exactly that — is true somewhere for it. A member that
     * already has a canonical mount of its own gets `serve`, and
     * §8.11.9's `rel=canonical` keeps pointing at its own domain.
     *
     * @throws CollectionRefused
     */
    private function mountMember(
        Collection $collection,
        Project $project,
        DomainMount $parentMount,
        string $prefix,
        string $mountExposure,
        int $position,
    ): DomainMount {
        $hasCanonical = DomainMount::query()
            ->where('project_id', $project->id)
            ->where('mode', 'canonical')
            ->exists();

        $mount = new DomainMount;

        try {
            $mount->forceFill([
                'id' => Uuid::v7(),
                'organisation_id' => $collection->organisation_id,
                'domain_id' => $parentMount->domain_id,
                'project_id' => $project->id,
                'path_prefix' => $prefix,
                'mode' => $hasCanonical ? 'serve' : 'canonical',
                'mount_exposure' => $mountExposure,
                'position' => $position,
            ])->save();
        } catch (UniqueConstraintViolationException) {
            // §10.5's `UNIQUE (domain_id, path_prefix)`. Something already
            // serves here — another collection's member, or a portal mount
            // configured by hand.
            throw CollectionRefused::of(CollectionRejection::PrefixTaken, $prefix);
        }

        return $mount;
    }
}
