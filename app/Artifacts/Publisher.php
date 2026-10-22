<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

use App\Artifacts\Exceptions\IngestRejected;
use App\Audit\ActorType;
use App\Audit\Audit;
use App\Models\Build;
use App\Models\BuildOutput;
use App\Models\Component;
use App\Models\ComponentMount;
use App\Models\ManifestBuild;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\ProjectVersionManifest;
use App\Models\VersionPointerEvent;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * Publishing, rollback and pinning — the §8.8.4–§8.8.8 pointer machinery.
 *
 * 🛑 **Publication is a compare-and-swap, and it is allowed to lose** (§8.8.4):
 * "a single compare-and-swap row update inside a transaction holding
 * `SELECT … FOR UPDATE` on the version row. Zero affected rows means another
 * build won, and that build MUST terminate as `success_unpublished`."
 *
 * The subtlety that makes this a real CAS rather than ceremony: the expected
 * pointer is read **before** the build's work begins, not inside the lock.
 * Inside the lock a comparison against a just-read value can never fail, which
 * would make the whole construction decorative. Captured at the start, it means
 * a build that began while the version served manifest 7 and finishes after
 * another build moved it to 8 discovers that it lost — which is the only way to
 * discover it, because the two builds never meet.
 *
 * 🛑 **Losing is not failing.** The losing build's artifacts are valid, stored
 * and immediately selectable; it simply is not the one being served. §10.3
 * gives it its own state for exactly this reason, and conflating it with
 * failure would have operators chasing phantom build errors every time two
 * builds finish together.
 */
final class Publisher
{
    public function __construct(
        private readonly ArtifactIngestor $ingestor,
        private readonly ArtifactStore $store,
        private readonly Quotas $quotas,
    ) {}

    /**
     * Ingest an uploaded tree and attempt to publish it.
     *
     * @param  string  $archivePath  a local file; a zip, tar or gzipped tar
     * @param  string|null  $actorId  raw 16 bytes, or null when the system did it
     *
     * @throws IngestRejected when the tree or the quota refuses it
     */
    public function publishUpload(
        ProjectVersion $version,
        string $archivePath,
        ?string $actorId = null,
    ): PublishOutcome {
        /*
         * The component is resolved here, not supplied by the caller. §17 gives
         * Phase 03 "exactly one degenerate component per project with a single
         * primary mount at `mount_path=''`", which makes it a property of
         * publishing rather than a decision an endpoint gets to make — and
         * §8.21.6 wants the runner to arrive as another caller of this method,
         * not as a second place that knows how components are arranged.
         */
        $component = $this->degenerateComponentFor($version);

        /*
         * 🛑 Read BEFORE the ingest, which is the work that takes time. This is
         * the "compare" half of the compare-and-swap, and capturing it here is
         * what gives a concurrent publish a window to win in. Reading it inside
         * the transaction below would compare a value against itself.
         */
        $expectedManifestId = $version->published_manifest_id;

        $buildId = Uuid::v7();
        $result = $this->ingestor->ingest($buildId, $archivePath);

        /*
         * §8.8.10: at ingest, from the authoritative manifest, exact. The bytes
         * are on the disk by now — they have to be, because "exact" means
         * counted rather than estimated — so a refusal here deletes them. That
         * is safe and it is cheap: the build never published, so no pointer
         * references the prefix, and §20.3 exempts a failed build's objects from
         * both the age floor and the quarantine precisely because they can never
         * have been served.
         */
        try {
            $this->quotas->assertArtifactBytesAvailable($version->organisation_id, $result->totalBytes);
        } catch (IngestRejected $rejection) {
            $this->store->deletePrefix($this->store->prefixFor($buildId));

            throw $rejection;
        }

        $build = $this->recordBuild($version, $component, $buildId, $result);

        return $this->flip(
            version: $version,
            build: $build,
            expectedManifestId: $expectedManifestId,
            reason: 'publish',
            actorId: $actorId,
        );
    }

    /**
     * Roll a version back to the manifest revision before the current one
     * (§8.8.5).
     *
     * 🛑 "Rollback MUST be the same pointer flip backwards, **plus a pin** that
     * blocks automatic republication until a human unpins." The pin is not
     * optional and it is not a nicety: without it the next successful build
     * immediately republishes the thing that was just rolled back, which is the
     * worst available response to somebody deciding a release was bad.
     *
     * The bytes are untouched. §8.8.5 requires the previous build to stay
     * "intact and immediately re-selectable", so a rollback writes one row and
     * moves nothing — which is also why it can be instant and why it restores
     * the previous build's bytes *exactly* rather than approximately.
     *
     * @param  string|null  $actorId  raw 16 bytes, or null when the system did it
     *
     * @throws \RuntimeException when there is no earlier revision to return to
     */
    public function rollback(ProjectVersion $version, string $reason, ?string $actorId = null): PublishOutcome
    {
        $current = $version->published_manifest_id;

        if ($current === null) {
            throw new \RuntimeException('Cannot roll back a version that is not published.');
        }

        $target = $this->revisionBefore($version, $current);

        if ($target === null) {
            throw new \RuntimeException('Cannot roll back: this version has only one published revision.');
        }

        return $this->flip(
            version: $version,
            build: $this->buildBehind($target),
            expectedManifestId: $current,
            reason: 'rollback',
            actorId: $actorId,
            manifest: $target,
            pinReason: $reason,
        );
    }

    /**
     * Release the pin a rollback left behind (§8.8.5).
     *
     * Deliberately a separate, deliberate act: "blocks automatic republication
     * **until a human unpins**". An automatic unpin on the next build would be
     * the pin not existing.
     *
     * @param  string|null  $actorId  raw 16 bytes, or null when the system did it
     */
    public function unpin(ProjectVersion $version, ?string $actorId = null): void
    {
        if (! $version->pinned) {
            return;
        }

        DB::transaction(function () use ($version, $actorId): void {
            $version->forceFill([
                'pinned' => false,
                'pinned_reason' => null,
                'pinned_at' => null,
                'pinned_by' => null,
            ])->save();

            Audit::record(
                action: 'version.unpinned',
                actorType: $actorId === null ? ActorType::System : ActorType::User,
                organisationId: $version->organisation_id,
                actorId: $actorId,
                subjectType: 'project_version',
                subjectId: $version->id,
            );
        });
    }

    /**
     * The one component Phase 03 gives a project, created on first publish.
     *
     * §17: "P03 creates exactly one degenerate component per project with a
     * single primary mount at `mount_path=''`, and P13 adds the write-side
     * behaviour that makes components first-class." Created lazily, because
     * Phase 03 has no component management surface and doing it at project
     * creation would have put a Phase 03 concern inside Phase 02's code.
     *
     * 🛑 `min_access` is snapshotted onto the mount (§8.7.7) and re-checked
     * after mount match at serve time, so a later widening of the component
     * cannot retroactively expose what was mounted under the old ceiling.
     */
    private function degenerateComponentFor(ProjectVersion $version): Component
    {
        $project = $version->project;

        if (! $project instanceof Project) {
            throw new \RuntimeException('A version without a project cannot be published.');
        }

        $component = Component::query()->where('key', $project->slug)->first();

        if (! $component instanceof Component) {
            $component = new Component;
            $component->forceFill([
                'organisation_id' => $project->organisation_id,
                'key' => $project->slug,
                'name' => $project->name,
                // The component may demand no more protection than the project
                // it was created for, or its own first mount would be refused.
                'min_access' => $project->visibility->value,
            ])->save();
        }

        $mount = ComponentMount::query()
            ->where('project_version_id', $version->id)
            ->where('component_id', $component->id)
            ->first();

        if (! $mount instanceof ComponentMount) {
            $mount = new ComponentMount;
            $mount->forceFill([
                'organisation_id' => $project->organisation_id,
                'project_version_id' => $version->id,
                'component_id' => $component->id,
                'mount_path' => '',
                'is_primary' => true,
                'min_access_snapshot' => $component->min_access->value,
            ])->save();
        }

        return $component;
    }

    /**
     * Persist the build and its per-format outputs from one ingest.
     *
     * Written after the ingest rather than before it so that a refused tree
     * leaves no row at all. A `queued` build row for an upload that turned out
     * to be a zip bomb is noise in every build list forever, and §8.19's build
     * history is meant to be a record of attempts to build, not of attempts to
     * upload.
     */
    private function recordBuild(
        ProjectVersion $version,
        Component $component,
        string $buildId,
        IngestResult $result,
    ): Build {
        return DB::transaction(function () use ($version, $component, $buildId, $result): Build {
            $build = new Build;
            $build->forceFill([
                'id' => $buildId,
                'organisation_id' => $version->organisation_id,
                'project_version_id' => $version->id,
                'component_id' => $component->id,
                'content_key' => $this->contentKeyForUpload($buildId),
                'state' => 'running',
                'file_count' => $result->fileCount,
                'total_bytes' => $result->totalBytes,
                'started_at' => now(),
            ])->save();

            foreach ($result->outputs as $output) {
                $row = new BuildOutput;
                $row->forceFill([
                    'organisation_id' => $version->organisation_id,
                    'build_id' => $buildId,
                    'format' => $output->format,
                    'storage_key' => $output->storageKey,
                    'file_count' => $output->fileCount,
                    'total_bytes' => $output->totalBytes,
                    'content_sha256' => $output->contentSha256,
                ])->save();
            }

            // The manifest DocUp emitted is an output too, and recording it is
            // what lets §8.8.9's sweep know the object exists without parsing
            // storage keys to guess at it.
            $manifestOutput = new BuildOutput;
            $manifestOutput->forceFill([
                'organisation_id' => $version->organisation_id,
                'build_id' => $buildId,
                'format' => 'manifest',
                'storage_key' => $result->manifestKey,
                'file_count' => 1,
                'total_bytes' => strlen($result->manifest->encode()),
                'content_sha256' => $result->contentSha256,
            ])->save();

            return $build;
        });
    }

    /**
     * The content key for a direct upload (§8.7.9).
     *
     * 🛑 Derived from the build id, so it is unique by construction, and that is
     * the honest answer rather than a shortcut. §8.7.9's content key exists so
     * that "the same inputs produce the same key" and a rebuild of unchanged
     * inputs is recognised rather than repeated — but a direct upload **has no
     * inputs**. Nobody can reproduce it: the uploader could send anything, and
     * two identical uploads a week apart are not the same build in any sense
     * that matters.
     *
     * Keying it on the output bytes instead would be worse than useless. It
     * would collide two deliberate re-publishes of an unchanged tree, which
     * §8.8 explicitly expects to produce a second build, and §8.8.1's store is
     * write-once so the second could not reuse the first's prefix anyway.
     *
     * The runner computes a real content key from source commit, configuration,
     * toolchain and `env_digest` when it arrives in Phase 06 — and §8.21.6 makes
     * it "the first consumer of this path, not a privileged special case", so it
     * supplies that key rather than this method being changed to guess one.
     */
    private function contentKeyForUpload(string $buildId): string
    {
        return hash('sha256', 'docup.upload:'.Uuid::toText($buildId));
    }

    /**
     * The one compare-and-swap, with the version row locked (§8.8.4).
     *
     * @param  Build|null  $build  the build being published, or the one behind a
     *                             rollback target; null only when a rollback
     *                             target's build row has gone
     * @param  ProjectVersionManifest|null  $manifest  an existing revision to
     *                                                 return to, or null to mint a new one
     * @param  string|null  $pinReason  set by a rollback; null leaves the pin alone
     */
    private function flip(
        ProjectVersion $version,
        ?Build $build,
        ?string $expectedManifestId,
        string $reason,
        ?string $actorId,
        ?ProjectVersionManifest $manifest = null,
        ?string $pinReason = null,
    ): PublishOutcome {
        return DB::transaction(function () use (
            $version,
            $build,
            $expectedManifestId,
            $reason,
            $actorId,
            $manifest,
            $pinReason,
        ): PublishOutcome {
            /*
             * 🛑 §8.8.4 names `SELECT … FOR UPDATE` on the version row
             * specifically. It serialises concurrent publishes of the SAME
             * version against each other while leaving every other version
             * alone — a table-level lock would make one busy project block the
             * whole installation, and no lock at all would let two builds both
             * read the old pointer and both believe they won.
             */
            $locked = ProjectVersion::query()->whereKey($version->id)->lockForUpdate()->first();

            if ($locked === null) {
                throw new \RuntimeException('The version disappeared while publishing.');
            }

            $target = $manifest ?? $this->mintManifest($locked, $build);

            /*
             * The compare-and-swap. `<=>` rather than `=` because the expected
             * value is null for a version that has never published, and `= NULL`
             * is never true in SQL — with `=` the very first publish of every
             * version would report that it had lost a race against nobody.
             */
            $affected = ProjectVersion::query()
                ->whereKey($locked->id)
                ->whereRaw('published_manifest_id <=> ?', [$expectedManifestId])
                ->update([
                    'published_manifest_id' => $target->id,
                    'previous_manifest_id' => $expectedManifestId,
                    // §8.8.6: the previous manifest stays resolvable for a
                    // bounded window, so a page loaded a second before the flip
                    // can still fetch its relative assets.
                    'soft_landing_until' => now()->addSeconds($this->softLandingSeconds()),
                    'published' => true,
                    'pinned' => $pinReason !== null ? true : $locked->pinned,
                    'pinned_reason' => $pinReason ?? $locked->pinned_reason,
                    'pinned_at' => $pinReason !== null ? now() : $locked->pinned_at,
                    'pinned_by' => $pinReason !== null ? $actorId : $locked->pinned_by,
                    'updated_at' => now(),
                ]);

            if ($affected === 0) {
                /*
                 * 🛑 Another build won. §8.8.4: this build terminates as
                 * `success_unpublished` — not failed. Its artifacts stay stored
                 * and selectable, which is what makes a later rollback to it
                 * possible.
                 */
                $build?->forceFill(['state' => 'success_unpublished', 'finished_at' => now()])->save();

                return new PublishOutcome(
                    published: false,
                    build: $build,
                    manifest: $target,
                    previousManifestId: $expectedManifestId,
                );
            }

            $build?->forceFill(['state' => 'published', 'finished_at' => now()])->save();

            $event = new VersionPointerEvent;
            $event->forceFill([
                'organisation_id' => $locked->organisation_id,
                'project_version_id' => $locked->id,
                'from_manifest_id' => $expectedManifestId,
                'to_manifest_id' => $target->id,
                'from_build_id' => $expectedManifestId === null
                    ? null
                    : $this->buildBehind($this->manifestById($expectedManifestId))?->id,
                'to_build_id' => $build?->id,
                'reason' => $reason,
                'actor_id' => $actorId,
            ])->save();

            Audit::record(
                action: $reason === 'rollback' ? 'version.rolled_back' : 'version.published',
                actorType: $actorId === null ? ActorType::System : ActorType::User,
                organisationId: $locked->organisation_id,
                actorId: $actorId,
                subjectType: 'project_version',
                subjectId: $locked->id,
                // 🛑 §8.22.5: identifiers only. No slugs, no file names, no
                // actor labels — the chain hashes what is here, and anything
                // erasure must later tombstone cannot be inside a hash.
                payload: [
                    'manifest_revision' => $target->revision,
                    'from_manifest' => $expectedManifestId === null ? null : Uuid::toText($expectedManifestId),
                    'to_manifest' => Uuid::toText($target->id),
                    'build' => $build === null ? null : Uuid::toText($build->id),
                ],
            );

            return new PublishOutcome(
                published: true,
                build: $build,
                manifest: $target,
                previousManifestId: $expectedManifestId,
            );
        });
    }

    /**
     * Create the next immutable manifest revision for a version (§8.8.3).
     *
     * Phase 03's degenerate case: one component, one primary mount at
     * `mount_path=''`. The *shape* is the real one — a list of mounts, each
     * naming the build that serves it — because §8.8.3 applies "from the first
     * phase that serves anything" and widening a degenerate manifest later is a
     * data change, while replacing a build pointer with a manifest pointer is
     * the un-retrofittable one.
     */
    private function mintManifest(ProjectVersion $version, ?Build $build): ProjectVersionManifest
    {
        $highest = ProjectVersionManifest::query()
            ->where('project_version_id', $version->id)
            ->max('revision');

        // max() returns null for a version with no manifests yet, so the first
        // revision is 1. Narrowed rather than cast, because `(int) $mixed` is
        // the kind of thing that turns a surprise into a zero — and revision 0
        // would collide with the next publish on the unique index.
        $revision = 1 + (is_numeric($highest) ? (int) $highest : 0);

        $mounts = [];

        /** @var list<ComponentMount> $rows */
        $rows = ComponentMount::query()
            ->where('project_version_id', $version->id)
            ->orderBy('mount_path')
            ->get()
            ->all();

        foreach ($rows as $mount) {
            /*
             * Every mount resolves to the build just produced, because Phase 03
             * has exactly one component per project. Phase 13 resolves each
             * mount's own selector (`latest_success`, `ref`, `pinned_build`) and
             * records the resolution as the append-only row §8.8.8 requires.
             */
            $mounts[] = [
                'mount_path' => $mount->mount_path,
                'component_id' => Uuid::toText($mount->component_id),
                'build_id' => $build === null ? null : Uuid::toText($build->id),
                'is_primary' => $mount->is_primary,
                'min_access' => $mount->min_access_snapshot->value,
            ];
        }

        return DB::transaction(function () use ($version, $build, $revision, $mounts): ProjectVersionManifest {
            $manifest = new ProjectVersionManifest;
            $manifest->forceFill([
                'organisation_id' => $version->organisation_id,
                'project_version_id' => $version->id,
                'revision' => $revision,
                'mounts_json' => ['schema' => 'docup.version-manifest/1', 'mounts' => $mounts],
            ])->save();

            if ($build !== null) {
                $link = new ManifestBuild;
                $link->forceFill([
                    'organisation_id' => $version->organisation_id,
                    'manifest_id' => $manifest->id,
                    'component_id' => $build->component_id,
                    'build_id' => $build->id,
                ])->save();
            }

            return $manifest;
        });
    }

    /**
     * The revision immediately before a given manifest, for a rollback target.
     *
     * By revision order rather than by `previous_manifest_id`, which is the
     * soft-landing pointer and is overwritten on every flip. Two publishes after
     * a bad release, `previous_manifest_id` names the bad release — rolling back
     * to it would be rolling forward.
     *
     * @param  string  $manifestId  raw 16 bytes
     */
    private function revisionBefore(ProjectVersion $version, string $manifestId): ?ProjectVersionManifest
    {
        $current = $this->manifestById($manifestId);

        if ($current === null) {
            return null;
        }

        return ProjectVersionManifest::query()
            ->where('project_version_id', $version->id)
            ->where('revision', '<', $current->revision)
            ->orderByDesc('revision')
            ->first();
    }

    /** @param  string  $manifestId  raw 16 bytes */
    private function manifestById(string $manifestId): ?ProjectVersionManifest
    {
        return ProjectVersionManifest::query()->whereKey($manifestId)->first();
    }

    /**
     * The build a manifest resolved to, in the degenerate single-component case.
     *
     * Null-tolerant throughout, because §10.4 lets a manifest outlive the build
     * row it named: `manifest_builds` cascades on build deletion, and §8.8.9's
     * sweep can remove a build whose artifacts have aged out. A pointer event
     * that cannot name a build id is still a true record of a manifest flip,
     * which is the thing §8.8.3 makes authoritative.
     */
    private function buildBehind(?ProjectVersionManifest $manifest): ?Build
    {
        if ($manifest === null) {
            return null;
        }

        $link = ManifestBuild::query()->where('manifest_id', $manifest->id)->first();

        return $link === null ? null : Build::query()->whereKey($link->build_id)->first();
    }

    private function softLandingSeconds(): int
    {
        $seconds = config('artifacts.soft_landing_seconds');

        return is_numeric($seconds) ? (int) $seconds : 300;
    }
}
