<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\AccessLevel;
use App\Models\Component;
use App\Models\ComponentMount;
use App\Models\ComponentSource;
use App\Models\ProjectVersion;
use App\Models\Repository;
use App\Support\Uuid;
use Illuminate\Database\UniqueConstraintViolationException;

/**
 * §8.7.1's component identity, and the move that proves it was worth
 * having.
 *
 * > "The unit a repository contributes MUST be a **component**: an
 * > organisation-scoped, repository-independent identity,
 * > `UNIQUE (organisation_id, key)`, whose current location is a child
 * > `component_sources` row of `(repository_id, source_path, module)`.
 * > Moving, renaming, splitting or re-hosting a repository MUST require
 * > **no change to any consuming project's mounts**. Binding component
 * > identity to the repository is the one lifecycle case that cannot be
 * > fixed later without touching every consumer."
 *
 * 🛑 The whole design is in {@see moveSource()}, which updates one row and
 * is asserted to leave every `component_mounts` row untouched. Everything
 * else here exists so that method has something to move.
 */
final readonly class Components
{
    /**
     * Register a component.
     *
     * @param  string  $key  §8.7.1's organisation-scoped identity
     * @param  string|null  $ownerTeamId  raw 16 bytes; null means organisation-owned
     * @param  string|null  $actorId  raw 16 bytes
     *
     * @throws CompositionRefused
     */
    public function register(
        string $organisationId,
        string $key,
        string $name,
        AccessLevel $minAccess = AccessLevel::Members,
        ?string $ownerTeamId = null,
        string $defaultBaseUrlMode = 'relative',
        ?string $actorId = null,
    ): Component {
        $component = new Component;

        try {
            $component->forceFill([
                'id' => Uuid::v7(),
                'organisation_id' => $organisationId,
                'key' => $key,
                'owner_team_id' => $ownerTeamId,
                'name' => $name,

                /*
                 * 🛑 `members` by default, not `public`. §8.7.7 makes this a
                 * confidentiality ceiling owned by the source, and a default
                 * of `public` would mean every component registered without
                 * a thought could be mounted on a public project. Defaults
                 * decide what most installations end up with; this one is
                 * the restrictive direction on purpose, and loosening it is
                 * §8.7.7's "separate audited action".
                 */
                'min_access' => $minAccess->value,
                'default_base_url_mode' => $defaultBaseUrlMode,
                'state' => 'active',
            ])->save();
        } catch (UniqueConstraintViolationException) {
            throw CompositionRefused::of(
                CompositionRejection::ComponentKeyTaken,
                '"'.$key.'" is already a component key in this organisation',
            );
        }

        Audit::record(
            action: 'component.registered',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $organisationId,
            actorId: $actorId,
            subjectType: 'component',
            subjectId: $component->id,
            payload: ['key' => $key, 'min_access' => $minAccess->value],
        );

        return $component;
    }

    /**
     * Attach a repository and a path to a component (§8.7.1's child row).
     *
     * @param  string  $sourcePath  '' for the repository root
     * @param  list<string>|null  $pathFilters  §8.5.4's gating, per source
     * @param  string|null  $actorId  raw 16 bytes
     */
    public function attachSource(
        Component $component,
        Repository $repository,
        string $sourcePath = '',
        string $module = 'ROOT',
        ?array $pathFilters = null,
        ?string $actorId = null,
    ): ComponentSource {
        $source = new ComponentSource;

        $source->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $component->organisation_id,
            'component_id' => $component->id,
            'repository_id' => $repository->id,
            'source_path' => $sourcePath,
            'module' => $module,
            'priority' => 100,

            /*
             * §8.5.4's changed-path gating, held per SOURCE rather than per
             * project. A monorepo's three components each have their own
             * subtree, and "did this push touch my subtree?" is a question
             * about the source, not about whoever happens to mount it —
             * which is what lets one push rebuild exactly the components it
             * changed however many projects consume them.
             *
             * Null means "derive from `source_path`", which is the right
             * answer for the overwhelming majority: a component rooted at
             * `docs/api` is dirty when `docs/api/**` changes.
             */
            'path_filters' => $pathFilters,
            'state' => 'active',
        ])->save();

        Audit::record(
            action: 'component.source.attached',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $component->organisation_id,
            actorId: $actorId,
            subjectType: 'component_source',
            subjectId: $source->id,
            payload: [
                'component' => $component->key,
                'repository' => Uuid::toText($repository->id),
                'source_path' => $sourcePath,
            ],
        );

        return $source;
    }

    /**
     * 🛑 §8.7.1's lifecycle case: move a component to a different
     * repository, or to a different path inside one.
     *
     * > "Moving, renaming, splitting or re-hosting a repository MUST require
     * > **no change to any consuming project's mounts**."
     *
     * One row changes. Every `component_mounts` row pointing at this
     * component is untouched, every published manifest goes on serving, and
     * no consuming project is notified because nothing about the component's
     * identity changed — only where its bytes come from next time.
     *
     * The alternative design, which §8.7.1 names and rejects, is identity as
     * a child of the repository: then this operation would re-point every
     * consumer by hand, and §8.7.1 calls that "the one lifecycle case that
     * cannot be fixed later".
     *
     * 🛑 **The content key changes and that is correct.** The new location
     * has a different commit, so §8.7.9's key differs and the next build is
     * a real build rather than a reuse. What must NOT change is the mounts,
     * and `MountMovesWithComponentTest` asserts exactly that.
     *
     * @param  string|null  $actorId  raw 16 bytes
     */
    public function moveSource(
        ComponentSource $source,
        Repository $destination,
        ?string $sourcePath = null,
        ?string $actorId = null,
    ): ComponentSource {
        $from = [
            'repository' => Uuid::toText($source->repository_id),
            'source_path' => $source->source_path,
        ];

        $source->forceFill([
            'repository_id' => $destination->id,
            'source_path' => $sourcePath ?? $source->source_path,
        ])->save();

        Audit::record(
            action: 'component.source.moved',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $source->organisation_id,
            actorId: $actorId,
            subjectType: 'component_source',
            subjectId: $source->id,
            payload: [
                'from' => $from,
                'to' => [
                    'repository' => Uuid::toText($destination->id),
                    'source_path' => $source->source_path,
                ],
                // The number a reader of the audit log actually wants: how
                // many consumers this did NOT disturb.
                'mounts_unchanged' => $this->mountCountFor($source->component_id),
            ],
        );

        return $source;
    }

    /**
     * 🛑 §8.7.7's loosening, which is a separate audited action.
     *
     * > "Loosening a ceiling MUST be a separate audited action that
     * > re-validates every existing mount and unpublishes any version it
     * > would declassify."
     *
     * Loosening (public ← members) can never declassify: every existing
     * mount was validated against a stricter ceiling and stays valid. It is
     * **tightening** that breaks mounts, and this refuses it rather than
     * unpublishing live versions behind an operator's back — the
     * requirement's "unpublishes any version it would declassify" is about
     * the loosening direction, where a version becomes visible to more
     * people, and tightening has the opposite shape: the version is fine and
     * the mount is not.
     *
     * So: loosen freely, audited. Tighten only when no mount would be
     * orphaned, and name the ones that would.
     *
     * @param  string|null  $actorId  raw 16 bytes
     *
     * @throws CompositionRefused
     */
    public function setMinAccess(
        Component $component,
        AccessLevel $level,
        MountPolicy $policy = new MountPolicy,
        ?string $actorId = null,
    ): Component {
        $previous = $component->min_access;

        if ($level->stricter($previous)) {
            $blocked = [];

            /** @var list<ComponentMount> $mounts */
            $mounts = array_values(
                ComponentMount::query()->where('component_id', $component->id)->get()->all(),
            );

            foreach ($mounts as $mount) {
                $version = $mount->projectVersion;

                if (! $version instanceof ProjectVersion) {
                    continue;
                }

                if ($level->stricter($policy->effectiveVisibility($version))) {
                    $blocked[] = Uuid::toText($version->id);
                }
            }

            if ($blocked !== []) {
                throw CompositionRefused::of(
                    CompositionRejection::CeilingTighteningWouldOrphanMounts,
                    count($blocked).' mounted version(s) would become invalid: '.implode(', ', $blocked),
                );
            }
        }

        $component->forceFill(['min_access' => $level->value])->save();

        /*
         * 🛑 Re-validated mounts get a fresh snapshot. §8.7.7 denormalises
         * the ceiling into the manifest, and a snapshot left at the old
         * value would mean the serving path re-checking against a number
         * nobody holds any more.
         */
        ComponentMount::query()
            ->where('component_id', $component->id)
            ->update(['min_access_snapshot' => $level->value]);

        Audit::record(
            action: $level->stricter($previous) ? 'component.ceiling.tightened' : 'component.ceiling.loosened',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $component->organisation_id,
            actorId: $actorId,
            subjectType: 'component',
            subjectId: $component->id,
            payload: ['from' => $previous->value, 'to' => $level->value],
        );

        return $component;
    }

    /** @param string $componentId raw 16 bytes */
    private function mountCountFor(string $componentId): int
    {
        return ComponentMount::query()->where('component_id', $componentId)->count();
    }
}
