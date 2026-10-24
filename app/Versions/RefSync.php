<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Versions;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\AccessLevel;
use App\Builds\RefResolver;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\Repository;
use App\Support\Uuid;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

/**
 * §8.6.1: branches and tags become reader-selectable versions, without a
 * human.
 *
 * > "The system MUST discover versions from git branches and tags and MUST
 * > create a reader-selectable version without human action."
 *
 * 🛑 **Nothing here deletes a version** (§8.6.15): "the version MUST be
 * deactivated rather than silently deleted, its URLs MUST continue to
 * resolve until an operator or an automation rule removes it, and removal
 * MUST be an automation-rule action (`delete_version`) triggered by ref
 * disappearance rather than by ref creation. Nothing may delete
 * reader-visible URLs without either an explicit rule or an explicit
 * action." A sync that ran against a provider having a bad morning would
 * otherwise take a project's documentation off the internet.
 *
 * 🛑 **Nothing here reactivates one either.** A ref that comes back brings
 * its version back into `ref_disappeared_at = null`, but an `active` an
 * operator turned off stays off — the two are different facts, which is why
 * §8.6.15 gets its own column rather than overloading `active`.
 */
final readonly class RefSync
{
    public function __construct(private RefResolver $refs) {}

    /**
     * Synchronise one project's versions against one repository's refs.
     *
     * @param  list<DiscoveredRef>|null  $refs  already-discovered refs, or null to advertise
     */
    public function sync(Project $project, Repository $repository, ?array $refs = null): SyncOutcome
    {
        $discovered = $refs ?? $this->discover($repository);
        $defaultBranch = $repository->default_branch;

        $existing = ProjectVersion::query()
            ->where('project_id', $project->id)
            ->whereNotNull('ref_name')
            ->get()
            ->keyBy(static fn (ProjectVersion $version): string => $version->ref_kind.':'.$version->ref_name);

        $created = [];
        $updated = [];
        $seen = [];

        foreach ($discovered as $ref) {
            $key = $ref->kind->value.':'.$ref->name;
            $seen[] = $key;
            $version = $existing->get($key);

            if ($version instanceof ProjectVersion) {
                $updated[] = $this->refresh($version, $ref);

                continue;
            }

            $created[] = $this->create($project, $ref, $defaultBranch);
        }

        $disappeared = $this->deactivateDisappeared($project, $existing, $seen);

        return new SyncOutcome($created, $updated, $disappeared);
    }

    /**
     * The refs a repository advertises, as values.
     *
     * 🛑 An annotated tag appears twice — once for the tag object and once
     * peeled to its commit as `<name>^{}` — and the peeled entry is the one
     * a build wants. {@see DiscoveredRef::fromAdvertisement()} drops the
     * peeled line so the tag is created once; this merges the commit back in
     * afterwards, so the version records the commit the tag resolves to
     * rather than the hash of the tag object itself.
     *
     * @return list<DiscoveredRef>
     */
    public function discover(Repository $repository): array
    {
        $advertised = $this->refs->advertise($repository->clone_url);

        $refs = [];
        $peeled = [];

        foreach ($advertised as $name => $sha) {
            if (str_starts_with($name, 'refs/tags/') && str_ends_with($name, '^{}')) {
                $peeled[substr($name, strlen('refs/tags/'), -3)] = $sha;

                continue;
            }

            $ref = DiscoveredRef::fromAdvertisement($name, $sha);

            if ($ref instanceof DiscoveredRef) {
                $refs[] = $ref;
            }
        }

        foreach ($refs as $index => $ref) {
            if ($ref->kind === RefKind::Tag && isset($peeled[$ref->name])) {
                $refs[$index] = $ref->withCommit($peeled[$ref->name]);
            }
        }

        return $refs;
    }

    /**
     * 🛑 §8.6.3's private inheritance, which is the one rule here that
     * cannot be got wrong quietly.
     *
     * > "A newly discovered version MUST inherit `private` whenever the
     * > project has ever had a non-public access rule, so that making a
     * > project public can never retroactively expose a version, and a new
     * > branch on a private project is never born public."
     *
     * **Ever**, not *is*. A project that was private in March and is public
     * today still has content written under the old understanding, and a
     * branch created tomorrow must not be born public because somebody
     * flipped a switch in between. `projects.has_ever_been_guarded` is a
     * latch that nothing clears; this reads it and the current visibility,
     * and takes the more restrictive of the two.
     */
    public static function bornVisibility(Project $project): AccessLevel
    {
        $current = $project->visibility;

        if ($project->has_ever_been_guarded) {
            /*
             * `restricted` rather than merely "not public": §12.3's lattice
             * makes `restricted` the narrowest level, and §8.6.3's purpose
             * is that a new version is never *more* visible than the project
             * has ever been. An operator who wants it wider says so.
             */
            return AccessLevel::Restricted;
        }

        return $current;
    }

    private function create(Project $project, DiscoveredRef $ref, ?string $defaultBranch): ProjectVersion
    {
        $taken = ProjectVersion::query()
            ->where('project_id', $project->id)
            ->where('language', 'en')
            ->pluck('slug')
            ->all();

        $slug = VersionSlug::fromRef($ref->name, array_values(array_map(strval(...), $taken)));

        $version = new ProjectVersion;
        $version->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $project->organisation_id,
            'project_id' => $project->id,
            'slug' => $slug,
            'ref_name' => $ref->name,
            'ref_kind' => $ref->kind->value,
            'ref_commit_sha' => $ref->commitSha,
            'ref_seen_at' => now(),
            'kind' => $ref->kind->versionKind(),

            /*
             * §8.6.12's language. `en` for a discovered ref, because a git
             * branch carries no language and guessing one from its name
             * would make `fr-fixes` a French translation. A translation is
             * configured, not inferred.
             */
            'language' => 'en',

            /*
             * §8.6.2's four axes, set independently at birth.
             *
             * 🛑 `active` yes and `published` NO. §8.6.1 asks for a
             * "reader-selectable version", which this is — it is in the
             * project's version list the moment it exists — but `published`
             * is §8.8.4's pointer flip and belongs to the build that
             * produces something to point at. A version born published with
             * no manifest is a 404 that claims to be a page.
             */
            'active' => true,
            'listed' => true,
            'published' => false,
            'visibility' => self::bornVisibility($project),
        ])->save();

        Audit::record(
            action: 'version.discovered',
            actorType: ActorType::System,
            subjectType: 'project_version',
            subjectId: $version->id,
            organisationId: $project->organisation_id,
            payload: [
                'ref' => $ref->name,
                'kind' => $ref->kind->value,
                'slug' => $slug,
                'visibility' => $version->visibility->value,
                'default_branch' => $defaultBranch,
            ],
        );

        return $version;
    }

    /** A ref we already had: record that it is still there, and where it points. */
    private function refresh(ProjectVersion $version, DiscoveredRef $ref): ProjectVersion
    {
        $version->forceFill([
            'ref_commit_sha' => $ref->commitSha,
            'ref_seen_at' => now(),

            /*
             * 🛑 Cleared, and nothing else is. A ref that came back is not
             * a version somebody reactivated: if an operator deactivated it
             * while the branch was gone, that decision stands. §8.6.15
             * separates "the ref disappeared" from "the version is off"
             * precisely so one cannot undo the other.
             */
            'ref_disappeared_at' => null,
        ])->save();

        return $version;
    }

    /**
     * 🛑 §8.6.15: deactivate, never delete.
     *
     * @param  Collection<string, ProjectVersion>  $existing
     * @param  list<string>  $seen
     * @return list<ProjectVersion>
     */
    private function deactivateDisappeared(Project $project, $existing, array $seen): array
    {
        $gone = [];

        foreach ($existing as $key => $version) {
            if (in_array($key, $seen, true) || $version->ref_disappeared_at !== null) {
                continue;
            }

            DB::transaction(function () use ($version): void {
                $version->forceFill([
                    'ref_disappeared_at' => now(),

                    /*
                     * Deactivated, so it leaves the flyout and stops being
                     * built — and still resolvable, because §8.6.15 says its
                     * URLs "MUST continue to resolve until an operator or an
                     * automation rule removes it".
                     *
                     * 🛑 Those two sentences look contradictory and are not.
                     * `active` is what §8.6.2 calls an axis and what
                     * `SnapshotVersion::isServable()` reads, so turning it
                     * off WOULD stop the URLs resolving. The version
                     * therefore keeps `active` and loses `listed`: absent
                     * from the list, reachable by the link somebody already
                     * has. That is exactly §8.6.2's `hidden`, which is the
                     * state this requirement is describing without naming.
                     */
                    'listed' => false,
                ])->save();
            });

            Audit::record(
                action: 'version.ref_disappeared',
                actorType: ActorType::System,
                subjectType: 'project_version',
                subjectId: $version->id,
                organisationId: $project->organisation_id,
                payload: [
                    'ref' => $version->ref_name,
                    'kind' => $version->ref_kind,
                    'slug' => $version->slug,
                    'note' => 'hidden, not deleted (§8.6.15); its URLs still resolve',
                ],
            );

            $gone[] = $version;
        }

        return $gone;
    }
}
