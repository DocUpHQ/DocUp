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
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Support\Uuid;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;

/**
 * The write side of §8.7.2's composition edge.
 *
 * Phase 03 created `component_mounts` with all three of §8.7.3's unique
 * constraints and nothing that wrote to it except a test fixture. This is
 * that write path, and it exists so the two rules a unique index cannot
 * express — §8.7.7's ceiling and §8.7.8's grant — are asked before a row is
 * inserted rather than discovered afterwards.
 *
 * 🛑 **Refusals are thrown, and the index is still the arbiter.** Every
 * check here is also a `UNIQUE` constraint, and the constraint is what
 * actually holds: two concurrent mounts of one component both pass the
 * check and one loses on the insert. The checks exist to make the common
 * case report something a human can read; the index exists to make the
 * race impossible. Catching the violation and re-reporting it as the same
 * identifier is what keeps the two answers identical.
 */
final readonly class Mounts
{
    public function __construct(private MountPolicy $policy = new MountPolicy) {}

    /**
     * Mount a component on a project version.
     *
     * @param  string  $mountPath  '' for the primary mount at the version root
     * @param  string|null  $actorId  raw 16 bytes, or null when the system did it
     *
     * @throws CompositionRefused
     */
    public function attach(
        ProjectVersion $version,
        Component $component,
        string $mountPath = '',
        bool $isPrimary = true,
        bool $isRequired = true,
        ?string $baseUrlMode = null,
        ?string $actorId = null,
    ): ComponentMount {
        $project = $version->project;

        $this->assertCanonicalPath($mountPath);
        $this->assertGranted($component, $actorId);
        $this->assertWithinCeiling($component, $version, $project);
        $this->assertRoomForAnotherMount($version, $component, $mountPath, $isPrimary);

        $mount = new ComponentMount;

        try {
            $mount->forceFill([
                'id' => Uuid::v7(),
                'organisation_id' => $version->organisation_id,
                'project_version_id' => $version->id,
                'component_id' => $component->id,
                'mount_path' => $mountPath,
                'base_url_mode' => $baseUrlMode,
                'selector_kind' => 'latest_success',
                'selector_value' => null,
                'is_required' => $isRequired,
                'is_primary' => $isPrimary,

                /*
                 * 🛑 §8.7.7's "denormalised into the published manifest".
                 * Snapshotted HERE, at mount time, from the component's
                 * ceiling as it is now — not read through the relation at
                 * publish time. §8.7.7 makes loosening a ceiling "a
                 * separate audited action that re-validates every existing
                 * mount", which only means anything if the mount records
                 * what it was validated against.
                 */
                'min_access_snapshot' => $component->min_access->value,
            ])->save();
        } catch (UniqueConstraintViolationException $collision) {
            // The index got there first. Re-reported as the refusal the
            // check above would have produced, so a caller sees one
            // identifier whichever way it was caught.
            throw CompositionRefused::of(
                $this->rejectionFor($collision->getMessage()),
                'refused by the database index',
            );
        }

        Audit::record(
            action: 'component.mounted',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $version->organisation_id,
            actorId: $actorId,
            subjectType: 'component_mount',
            subjectId: $mount->id,
            payload: [
                'component' => $component->key,
                'project_version' => Uuid::toText($version->id),
                'mount_path' => $mountPath,
                'min_access' => $component->min_access->value,
            ],
        );

        return $mount;
    }

    /**
     * 🛑 §8.7.3's half that an index cannot express, checked at publish.
     *
     * > "the two halves the index cannot enforce — that **at least one**
     * > exists, and that it sits at `mount_path=''` — MUST be enforced at
     * > publish time, which fails closed when either does not hold."
     *
     * MySQL has no partial unique index, so the generated `primary_marker`
     * column enforces *at most one*. Nothing in the schema can require that
     * one exists, because a version with no mounts at all is a legitimate
     * intermediate state — it is only publishing it that is not.
     *
     * @throws CompositionRefused
     */
    public function assertPublishable(ProjectVersion $version): void
    {
        /** @var list<ComponentMount> $mounts */
        $mounts = array_values(
            ComponentMount::query()->where('project_version_id', $version->id)->get()->all(),
        );

        $primary = null;

        foreach ($mounts as $mount) {
            if ($mount->is_primary) {
                $primary = $mount;
            }
        }

        if (! $primary instanceof ComponentMount) {
            throw CompositionRefused::of(
                CompositionRejection::PrimaryMountMissing,
                'a version with no primary mount has no root index.html, no 404.html and no theme assets',
            );
        }

        if ($primary->mount_path !== '') {
            throw CompositionRefused::of(
                CompositionRejection::PrimaryMountNotAtRoot,
                'the primary mount is at "'.$primary->mount_path.'"',
            );
        }

        /*
         * 🛑 §8.7.7's ceiling again, at publish rather than at mount.
         *
         * A mount validated in March can be invalid in June: the project's
         * visibility may have been loosened, or the component's ceiling
         * tightened. §8.7.7 calls for re-validation on both of those paths,
         * and this is the backstop that makes a missed one fail closed
         * rather than publish a declassified version.
         */
        foreach ($mounts as $mount) {
            $component = $mount->component;

            if (! $component instanceof Component) {
                continue;
            }

            if (! $this->policy->permitsMount($component, $version)) {
                throw CompositionRefused::of(
                    CompositionRejection::CeilingExceeded,
                    $component->key.' requires '.$component->min_access->value
                        .' and this version is effectively '
                        .$this->policy->effectiveVisibility($version)->value,
                );
            }
        }
    }

    /** @throws CompositionRefused */
    private function assertGranted(Component $component, ?string $actorId): void
    {
        if (! $this->policy->permitsActor($component, $actorId)) {
            throw CompositionRefused::of(
                CompositionRejection::GrantMissing,
                'no component_grants row lets this actor mount '.$component->key,
            );
        }
    }

    /** @throws CompositionRefused */
    private function assertWithinCeiling(Component $component, ProjectVersion $version, ?Project $project): void
    {
        if ($this->policy->permitsMount($component, $version, $project)) {
            return;
        }

        throw CompositionRefused::of(
            CompositionRejection::CeilingExceeded,
            $component->key.' requires '.$component->min_access->value
                .' and this version is effectively '
                .$this->policy->effectiveVisibility($version, $project)->value,
        );
    }

    /**
     * @throws CompositionRefused
     */
    private function assertRoomForAnotherMount(
        ProjectVersion $version,
        Component $component,
        string $mountPath,
        bool $isPrimary,
    ): void {
        /** @var list<ComponentMount> $existing */
        $existing = array_values(
            ComponentMount::query()->where('project_version_id', $version->id)->get()->all(),
        );

        foreach ($existing as $mount) {
            if ($mount->component_id === $component->id) {
                throw CompositionRefused::of(
                    CompositionRejection::ComponentAlreadyMounted,
                    $component->key.' is already mounted at "'.$mount->mount_path.'"',
                );
            }

            if ($mount->mount_path === $mountPath) {
                throw CompositionRefused::of(
                    CompositionRejection::MountPathTaken,
                    '"'.$mountPath.'" is taken',
                );
            }

            if ($isPrimary && $mount->is_primary) {
                throw CompositionRefused::of(
                    CompositionRejection::PrimaryMountExists,
                    'a version has exactly one primary mount (§8.7.3)',
                );
            }
        }

        /*
         * 🛑 §17 Phase 13: "Explicitly not in scope: More than one component
         * per project version (P14)."
         *
         * Refused rather than allowed-and-untested. The schema accommodates
         * it and the resolver already reads a list of mounts, but §8.7.6's
         * nav splicing, §8.7.14's collision policy and §8.7.15's shadowing
         * refusal are all P14's — a second mount today would serve with
         * none of them, which is a worse outcome than a clear refusal
         * naming the phase that lifts it.
         */
        if ($existing !== []) {
            throw CompositionRefused::of(
                CompositionRejection::MultipleMountsNotYetSupported,
                'more than one component per project version arrives in Phase 14 (§8.7.6, §8.7.14, §8.7.15)',
            );
        }
    }

    /**
     * A mount path is a path prefix, not a URL.
     *
     * No leading or trailing slash, no dot segments, no empty segments.
     * `''` is the root and is the only empty value accepted. The resolver
     * matches on segment boundaries (§7.3), so a path with a trailing slash
     * would be a prefix that never matches and a mount nothing ever reaches.
     *
     * @throws CompositionRefused
     */
    private function assertCanonicalPath(string $mountPath): void
    {
        if ($mountPath === '') {
            return;
        }

        if (preg_match('#^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$#', $mountPath) !== 1) {
            throw CompositionRefused::of(
                CompositionRejection::MountPathNotCanonical,
                '"'.$mountPath.'" is not a canonical mount path',
            );
        }
    }

    /**
     * Which of §8.7.3's three indexes refused.
     *
     * Read from the constraint name, because MySQL's message names it and a
     * refusal that said only "the database said no" would leave an operator
     * guessing which of three rules they broke.
     */
    private function rejectionFor(string $message): CompositionRejection
    {
        if (str_contains($message, 'component_mounts_component_unique')) {
            return CompositionRejection::ComponentAlreadyMounted;
        }

        if (str_contains($message, 'component_mounts_primary_unique')) {
            return CompositionRejection::PrimaryMountExists;
        }

        return CompositionRejection::MountPathTaken;
    }

    /**
     * Detach a mount.
     *
     * 🛑 §8.7.20: "A published manifest and its builds MUST keep serving
     * unchanged when a component becomes orphaned, a repository is retired
     * or a mount is detached." So this removes the edge and touches no
     * manifest — the live version goes on serving the bytes it was
     * published with, and the detachment takes effect at the next publish,
     * which §8.7.20's second sentence makes fail closed if a required mount
     * cannot resolve.
     *
     * @param  string|null  $actorId  raw 16 bytes
     */
    public function detach(ComponentMount $mount, ?string $actorId = null): void
    {
        $organisationId = $mount->organisation_id;
        $mountId = $mount->id;
        $componentId = $mount->component_id;

        DB::transaction(static function () use ($mount): void {
            $mount->delete();
        });

        Audit::record(
            action: 'component.unmounted',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $organisationId,
            actorId: $actorId,
            subjectType: 'component_mount',
            subjectId: $mountId,
            payload: ['component' => Uuid::toText($componentId)],
        );
    }

    /** The access level a published mount was validated against (§8.7.7). */
    public function snapshotFor(ComponentMount $mount): AccessLevel
    {
        return $mount->min_access_snapshot;
    }
}
