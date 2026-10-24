<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Versions;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Models\Project;
use App\Models\ProjectVersion;

/**
 * §8.6.4's `latest` and `stable`, as the two ordered algorithms it states.
 *
 * > "The system MUST derive `latest` and `stable` by one stated ordered
 * > algorithm, because every migrating team checks these first. For
 * > `stable`: (1) an explicit per-project override; (2) a ref literally
 * > named `stable`; (3) the highest **tag** by the project's configured
 * > comparator, prereleases excluded; (4) the highest branch by the same
 * > comparator; (5) no `stable` at all, which is a valid state and MUST NOT
 * > fall back to the default branch. For `latest`: (1) an explicit override;
 * > (2) a ref literally named `latest`; (3) the repository's default
 * > branch."
 *
 * 🛑 **Step 5 is the one that gets implemented wrong.** "No `stable` at all
 * ... MUST NOT fall back to the default branch" is an instruction to return
 * nothing, and the tempting mistake is to treat a missing `stable` as a
 * caller error and hand back `main`. A project with no release tags has no
 * stable release, and a `stable` that quietly means `main` is a URL readers
 * bookmark believing it is pinned.
 *
 * 🛑 **The comparator comes from the project** (§8.6.4, §8.6.5). Nothing
 * here sorts with `version_compare` or `sort`, because the same comparator
 * has to produce the flyout order — a `stable` derived one way and a list
 * ordered another is the specific contradiction that sentence forbids.
 */
final readonly class ChannelResolver
{
    /**
     * §8.6.4's `stable`, or null.
     *
     * @param  list<ProjectVersion>  $versions  the project's candidate versions
     */
    public function stable(Project $project, array $versions): ?ProjectVersion
    {
        $comparator = VersionComparator::fromStored($project->version_comparator);
        $candidates = $this->eligible($versions);

        // (1) an explicit per-project override.
        $override = $this->overrideFrom($candidates, $project->stable_version_id);

        if ($override instanceof ProjectVersion) {
            return $override;
        }

        // (2) a ref literally named `stable`.
        $literal = $this->namedLiterally($candidates, 'stable');

        if ($literal instanceof ProjectVersion) {
            return $literal;
        }

        // (3) the highest TAG, prereleases excluded.
        $fromTags = $this->highestOf($comparator, $candidates, RefKind::Tag, excludePrereleases: true);

        if ($fromTags instanceof ProjectVersion) {
            return $fromTags;
        }

        // (4) the highest BRANCH, by the same comparator.
        $fromBranches = $this->highestOf($comparator, $candidates, RefKind::Branch, excludePrereleases: true);

        if ($fromBranches instanceof ProjectVersion) {
            return $fromBranches;
        }

        /*
         * (5) 🛑 Nothing. Not the default branch, not the newest version,
         * not the first row. §8.6.4 names this as "a valid state".
         */
        return null;
    }

    /**
     * §8.6.4's `latest`, or null.
     *
     * Three steps rather than five, and no comparator: `latest` means "the
     * tip of development", which is a fact about the repository rather than
     * about version numbers. A project whose default branch is gone has no
     * `latest`, for the same reason step 5 above returns null.
     *
     * @param  list<ProjectVersion>  $versions
     */
    public function latest(Project $project, array $versions, ?string $defaultBranch = null): ?ProjectVersion
    {
        $candidates = $this->eligible($versions);

        $override = $this->overrideFrom($candidates, $project->latest_version_id);

        if ($override instanceof ProjectVersion) {
            return $override;
        }

        $literal = $this->namedLiterally($candidates, 'latest');

        if ($literal instanceof ProjectVersion) {
            return $literal;
        }

        if ($defaultBranch === null || $defaultBranch === '') {
            return null;
        }

        foreach ($candidates as $version) {
            if ($version->ref_kind === RefKind::Branch->value && $version->ref_name === $defaultBranch) {
                return $version;
            }
        }

        return null;
    }

    /**
     * Derive both channels and store them, recording what moved.
     *
     * 🛑 The pointers are **stored**, not computed per request, for the
     * reason §8.6.14 gives about the default version: §8.9.7's empty-path
     * redirect and §8.11.5's 404 chain read them on the serving path, and a
     * derivation that ran there would put a comparator and a version list
     * in front of every request that omits a version.
     *
     * Audited on change and only on change. A sync that found nothing new
     * re-derives the same two pointers, and an audit event per sync would
     * bury the one that mattered.
     *
     * @param  list<ProjectVersion>  $versions
     */
    public function reconcile(Project $project, array $versions, ?string $defaultBranch = null): ChannelOutcome
    {
        $stable = $this->stable($project, $versions);

        /*
         * 🛑 Without a default branch, `latest` is VERIFIED rather than
         * derived, and the distinction matters.
         *
         * §8.6.4's `latest` has no comparator: its last step is "the
         * repository's default branch", which only a caller holding the
         * repository can supply. A reconciliation triggered by something
         * else — a deactivation, a wipe — does not have one, and the two
         * wrong answers are both available: deriving null would unset
         * `latest` every time somebody deactivated an unrelated version,
         * and keeping the stored pointer blindly would leave it aimed at a
         * version that has just been switched off.
         *
         * So the stored pointer is kept if it is still eligible and cleared
         * if it is not. A caller that can say which branch is the default
         * gets the full derivation.
         */
        $latest = $defaultBranch === null
            ? $this->stillEligible($versions, $project->resolved_latest_version_id)
            : $this->latest($project, $versions, $defaultBranch);

        $before = [
            'stable' => $this->resolvedIdOf($project, 'stable'),
            'latest' => $this->resolvedIdOf($project, 'latest'),
        ];

        $project->forceFill([
            'resolved_stable_version_id' => $stable?->id,
            'resolved_latest_version_id' => $latest?->id,
        ])->save();

        $moved = [];

        foreach (['stable' => $stable, 'latest' => $latest] as $channel => $version) {
            if (($before[$channel] ?? null) === $version?->id) {
                continue;
            }

            $moved[] = $channel;

            Audit::record(
                action: 'version.channel_moved',
                actorType: ActorType::System,
                organisationId: $project->organisation_id,
                subjectType: 'project',
                subjectId: $project->id,
                payload: [
                    'channel' => $channel,
                    'from' => $before[$channel] === null ? null : bin2hex($before[$channel]),
                    'to' => $version === null ? null : bin2hex($version->id),
                    'slug' => $version?->slug,
                    'comparator' => (string) $project->version_comparator,
                ],
            );
        }

        return new ChannelOutcome($stable, $latest, $moved);
    }

    /**
     * The stored pointer, if it still names an eligible version.
     *
     * @param  list<ProjectVersion>  $versions
     */
    private function stillEligible(array $versions, ?string $versionId): ?ProjectVersion
    {
        if ($versionId === null || $versionId === '') {
            return null;
        }

        foreach ($this->eligible($versions) as $version) {
            if ($version->id === $versionId) {
                return $version;
            }
        }

        return null;
    }

    /**
     * Versions a channel may point at.
     *
     * 🛑 `active` only, and deliberately not `published`. A channel is a
     * pointer at a *version*, and §8.6.2 keeps the axes independent — a
     * version that is active and not yet published is still what `stable`
     * means, and the serving layer answers the "nothing published" case
     * with its own 404 rather than by making the pointer lie. An inactive
     * version is different: it has been switched off, and a channel
     * pointing at one would resolve to nothing with no way for a reader to
     * tell why.
     *
     * A version whose ref has disappeared is excluded for the same reason,
     * which is also what makes `stable` move off a deleted release tag
     * without anybody deleting the version (§8.6.15).
     *
     * @param  list<ProjectVersion>  $versions
     * @return list<ProjectVersion>
     */
    private function eligible(array $versions): array
    {
        return array_values(array_filter(
            $versions,
            static fn (ProjectVersion $version): bool => $version->active
                && $version->ref_disappeared_at === null,
        ));
    }

    /**
     * @param  list<ProjectVersion>  $candidates
     */
    private function overrideFrom(array $candidates, ?string $versionId): ?ProjectVersion
    {
        if ($versionId === null) {
            return null;
        }

        foreach ($candidates as $version) {
            if ($version->id === $versionId) {
                return $version;
            }
        }

        /*
         * 🛑 An override pointing at a version that is gone or inactive
         * falls THROUGH to the next step rather than resolving to nothing.
         * An operator who pinned `stable` to a version somebody later
         * deactivated should get the derived answer, not a project whose
         * `stable` is permanently broken until they notice.
         */
        return null;
    }

    /**
     * §8.6.4's step 2: "a ref literally named `stable`" / `latest`.
     *
     * Matched on the REF NAME, not the slug. A branch called `stable` and a
     * version somebody renamed to `stable` are different things, and only
     * the first is what the author meant.
     *
     * @param  list<ProjectVersion>  $candidates
     */
    private function namedLiterally(array $candidates, string $name): ?ProjectVersion
    {
        foreach ($candidates as $version) {
            if ($version->ref_name === $name) {
                return $version;
            }
        }

        return null;
    }

    /**
     * @param  list<ProjectVersion>  $candidates
     */
    private function highestOf(
        VersionComparator $comparator,
        array $candidates,
        RefKind $kind,
        bool $excludePrereleases,
    ): ?ProjectVersion {
        $byRef = [];

        foreach ($candidates as $version) {
            if ($version->ref_kind === $kind->value && is_string($version->ref_name)) {
                $byRef[$version->ref_name] = $version;
            }
        }

        $highest = $comparator->highest(array_keys($byRef), $excludePrereleases);

        return $highest === null ? null : $byRef[$highest];
    }

    /** The stored pointer, as raw bytes or null. */
    private function resolvedIdOf(Project $project, string $channel): ?string
    {
        $value = $project->getAttribute('resolved_'.$channel.'_version_id');

        return is_string($value) && $value !== '' ? $value : null;
    }
}
