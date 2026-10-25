<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Versions;

use App\Artifacts\ArtifactReaper;
use App\Audit\ActorType;
use App\Audit\Audit;
use App\Automation\AutomationAction;
use App\Models\Build;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Support\Invalidation;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * §8.6.6's rename and §8.6.7's bulk operations — the write side an operator
 * reaches.
 *
 * > "Slugs MUST be editable, 🛑 MUST NOT collide with any reserved segment
 * > (`_`, a language code, a collection alias), and a renamed slug MUST
 * > leave a working 301 behind it."
 *
 * > "The system MUST support bulk version activate/deactivate and a 'wipe
 * > version' action that discards artifacts while retaining the version
 * > row."
 *
 * 🛑 **The 301 is written in the same transaction as the rename.** A rename
 * that committed and a history row that did not is a URL that 404s for
 * everyone who had the old link — which is the entire failure the
 * requirement exists to prevent, arriving by a different route.
 */
final readonly class VersionOperations
{
    public function __construct(
        /*
         * 🛑 A reaper, not a store. §8.8.2 gives the artifact tree one
         * write path and deletion is a write; this class tried holding a
         * store directly and the architecture test refused it, rightly —
         * a version wipe and §8.8.9's collector are two callers of one
         * operation, and two copies of it would be two places that know
         * how a build's bytes are addressed.
         */
        private ArtifactReaper $reaper,
        private ChannelResolver $channels = new ChannelResolver,
        private DefaultVersionPointer $defaultPointer = new DefaultVersionPointer,
    ) {}

    /**
     * §8.6.6: rename a version, leaving a 301 behind.
     *
     * @param  string|null  $actorId  raw 16 bytes, or null when the system did it
     *
     * @throws VersionRefused
     */
    public function rename(ProjectVersion $version, string $slug, ?string $actorId = null): ProjectVersion
    {
        $normalised = VersionSlug::normalise($slug);

        if ($normalised !== $slug) {
            /*
             * 🛑 Refused rather than silently normalised. An operator who
             * typed `Release 2.0` and got `release-2.0` without being told
             * has a slug they did not choose in URLs they will quote; one
             * who is told can decide. The automatic path (`RefSync`) goes
             * through `VersionSlug::fromRef()` and never reaches here.
             */
            throw VersionRefused::of(
                VersionRejection::SlugNotNormalised,
                'try "'.$normalised.'"',
            );
        }

        if (VersionSlug::isReserved($normalised)) {
            throw VersionRefused::of(VersionRejection::SlugReserved, $normalised);
        }

        if ($normalised === $version->slug) {
            return $version;
        }

        $taken = ProjectVersion::query()
            ->where('project_id', $version->project_id)
            ->where('language', $version->language)
            ->whereKeyNot($version->id)
            ->where('slug', $normalised)
            ->exists();

        if ($taken) {
            throw VersionRefused::of(VersionRejection::SlugTaken, $normalised);
        }

        $previous = $version->slug;

        DB::transaction(function () use ($version, $normalised, $previous): void {
            /*
             * 🛑 The history row FIRST, and the unique key is why the order
             * is safe either way: `version_slug_history_unique` is
             * (project, language, slug), so a slug being freed by this very
             * rename could already be in the table from an earlier one. The
             * upsert displaces it, because a former slug points at exactly
             * one version and the most recent claim is the right one.
             */
            DB::table('project_version_slug_history')->upsert(
                [[
                    'id' => Uuid::v7(),
                    'organisation_id' => $version->organisation_id,
                    'project_id' => $version->project_id,
                    'project_version_id' => $version->id,
                    'language' => $version->language,
                    'slug' => $previous,
                    'created_at' => now(),
                ]],
                ['project_id', 'language', 'slug'],
                ['project_version_id', 'created_at'],
            );

            /*
             * 🛑 And the NEW slug is removed from the history, because a
             * version reclaiming a slug it once had must not redirect to
             * itself. §8.11.3's runtime hop cap would catch the loop; a
             * redirect that is caught by a hop cap is still a redirect
             * nobody should have served.
             */
            DB::table('project_version_slug_history')
                ->where('project_id', $version->project_id)
                ->where('language', $version->language)
                ->where('slug', $normalised)
                ->delete();

            $version->forceFill(['slug' => $normalised])->save();

            /*
             * §10.8: a version's URL changed, so every resolution cache
             * entry keyed on the old routing epoch is addressing a URL that
             * no longer exists. `version pointer change` is one of the four
             * causes the registry names, and the registry is the only thing
             * that knows how an epoch advances.
             */
            Invalidation::bumpRouting(
                projectId: $version->project_id,
                cause: 'version pointer change',
                organisationId: $version->organisation_id,
            );
        });

        Audit::record(
            action: 'version.renamed',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $version->organisation_id,
            actorId: $actorId,
            subjectType: 'project_version',
            subjectId: $version->id,
            payload: ['from' => $previous, 'to' => $normalised, 'language' => $version->language],
        );

        return $version;
    }

    /**
     * §8.6.7's bulk activate/deactivate.
     *
     * 🛑 One audit event per version, not one for the batch. An operator
     * deactivating forty versions has made forty decisions a reader will
     * notice, and §8.22's chain is what somebody reads afterwards to find
     * out which — a single "bulk_deactivate (40)" event answers "how many"
     * and not "which".
     *
     * @param  list<ProjectVersion>  $versions
     * @param  string|null  $actorId  raw 16 bytes
     * @return int how many actually changed
     */
    public function setActive(array $versions, bool $active, ?string $actorId = null): int
    {
        $changed = 0;

        foreach ($versions as $version) {
            if ($version->active === $active) {
                continue;
            }

            $version->forceFill(['active' => $active])->save();
            $changed++;

            Audit::record(
                action: $active ? 'version.activated' : 'version.deactivated',
                actorType: $actorId === null ? ActorType::System : ActorType::User,
                organisationId: $version->organisation_id,
                actorId: $actorId,
                subjectType: 'project_version',
                subjectId: $version->id,
                payload: ['slug' => $version->slug],
            );
        }

        if ($changed > 0) {
            // One bump for the batch, because the epoch is a counter rather
            // than a log: forty increments and one increment address the
            // same new cache keys, and §8.22's chain already has the forty
            // events above.
            Invalidation::bumpRouting(
                projectId: $versions[0]->project_id,
                cause: 'version pointer change',
                organisationId: $versions[0]->organisation_id,
                actorId: $actorId,
            );

            $this->reconcilePointers($versions[0], $actorId);
        }

        return $changed;
    }

    /**
     * §8.6.7's "wipe version": discard the artifacts, keep the row.
     *
     * 🛑 **The row is what makes this different from a delete**, and the
     * difference is a reader's. A deleted version's URLs resolve to
     * nothing; a wiped version's resolve to a 404 that knows what it is,
     * which §8.11.5's chain can then answer with the default version's
     * `404.html` rather than the branded built-in.
     *
     * 🛑 **The published pointer is cleared before the bytes go.** The
     * other order leaves a window in which the version is published and its
     * artifacts are not there — a 502 from the edge rather than a 404,
     * because the handoff points at a file the store no longer has.
     *
     * @param  string|null  $actorId  raw 16 bytes
     * @return int how many builds' artifacts were discarded
     */
    public function wipe(ProjectVersion $version, ?string $actorId = null): int
    {
        $builds = Build::query()
            ->where('project_version_id', $version->id)
            ->get();

        DB::transaction(function () use ($version): void {
            $version->forceFill([
                'published' => false,
                'published_manifest_id' => null,
                'previous_manifest_id' => null,
                'soft_landing_until' => null,
                'wiped_at' => now(),
                'serving_epoch' => Invalidation::servingEpochIncrement(),
            ])->save();
        });

        $discarded = $this->reaper->discardAll($builds);

        Audit::record(
            action: 'version.wiped',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $version->organisation_id,
            actorId: $actorId,
            subjectType: 'project_version',
            subjectId: $version->id,
            payload: ['slug' => $version->slug, 'builds_discarded' => $discarded],
        );

        $this->reconcilePointers($version, $actorId);

        return $discarded;
    }

    /**
     * §8.6.15's `delete_version`: the row goes, and the URLs with it.
     *
     * > "removal MUST be an automation-rule action (`delete_version`)
     * > triggered by ref disappearance rather than by ref creation. Nothing
     * > may delete reader-visible URLs without either an explicit rule or an
     * > explicit action."
     *
     * 🛑 **The only operation in DocUp that destroys reader-visible URLs**,
     * which is why it is not reachable from a sync, not reachable from a
     * build, and reachable from an automation rule only when that rule is
     * attached to `version_disappeared`
     * ({@see AutomationAction::isValidFor()}).
     *
     * It wipes first and deletes second, so the artifacts go through §8.8.2's
     * one write path rather than being orphaned by a cascade. A deleted row
     * whose bytes remain is storage nothing will ever reclaim: the collector
     * of §8.8.9 finds builds by their version, and the version is gone.
     *
     * 🛑 The slug history goes too — by cascade, declared on the foreign
     * key. A 301 pointing at a version that no longer exists is a redirect
     * to a 404, which is worse than the 404 the reader would have got
     * directly: two round trips to the same answer, and a search engine that
     * believes the URL moved rather than that it went.
     *
     * @param  string|null  $actorId  raw 16 bytes
     * @return int how many builds' artifacts were discarded
     */
    public function delete(ProjectVersion $version, ?string $actorId = null): int
    {
        $discarded = $this->wipe($version, $actorId);

        $project = $version->project;
        $organisationId = $version->organisation_id;
        $slug = $version->slug;

        $version->delete();

        Audit::record(
            action: 'version.deleted',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $organisationId,
            actorId: $actorId,
            subjectType: 'project_version',
            subjectId: $version->id,
            payload: ['slug' => $slug, 'builds_discarded' => $discarded],
        );

        if ($project instanceof Project) {
            Invalidation::bumpRouting(
                projectId: $project->id,
                cause: 'version pointer change',
                organisationId: $organisationId,
                actorId: $actorId,
            );

            /** @var list<ProjectVersion> $remaining */
            $remaining = array_values(
                ProjectVersion::query()->where('project_id', $project->id)->get()->all(),
            );

            $channels = $this->channels->reconcile($project, $remaining);

            $this->defaultPointer->reconcile($project, $remaining, $channels, $actorId);
        }

        return $discarded;
    }

    /**
     * 🛑 §8.6.14: the default version pointer "MUST be re-pointed
     * automatically with an audit event when its target is deleted or
     * deactivated".
     *
     * Called from every operation that can make a version unusable, rather
     * than from a read. The pointer is a stored fact (§8.6.14's own words),
     * and the three readers on the serving path — §8.9.7's empty-path
     * redirect, §8.6.10's `/page/` resolution and §8.11.5's 404 chain —
     * must find it already correct.
     */
    private function reconcilePointers(ProjectVersion $any, ?string $actorId): void
    {
        $project = $any->project;

        if (! $project instanceof Project) {
            return;
        }

        /** @var list<ProjectVersion> $versions */
        $versions = array_values(
            ProjectVersion::query()->where('project_id', $project->id)->get()->all(),
        );

        $channels = $this->channels->reconcile($project, $versions);

        $this->defaultPointer->reconcile($project, $versions, $channels, $actorId);
    }

    /**
     * The version a former slug redirects to (§8.6.6), or null.
     *
     * Returns the version rather than a path, because the caller knows the
     * scheme — §8.6.9's three put the slug in different places, and a
     * helper returning `/en/v2/` would be wrong for two of them.
     */
    public function redirectTargetFor(Project $project, string $language, string $slug): ?ProjectVersion
    {
        $row = DB::table('project_version_slug_history')
            ->where('project_id', $project->id)
            ->where('language', $language)
            ->where('slug', $slug)
            ->first();

        if ($row === null || ! is_string($row->project_version_id)) {
            return null;
        }

        $version = ProjectVersion::query()->whereKey($row->project_version_id)->first();

        /*
         * 🛑 A history row pointing at a version that is gone or inactive
         * redirects nowhere. Serving a 301 to a URL that 404s is worse than
         * the 404 itself: a crawler follows it, caches the redirect, and
         * comes back to the same dead end tomorrow.
         */
        return $version instanceof ProjectVersion && $version->active ? $version : null;
    }
}
