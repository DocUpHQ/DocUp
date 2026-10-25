<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

use App\Builds\PathGlob;
use App\Models\Build;
use App\Models\ComponentMount;
use App\Models\ComponentSource;
use App\Models\ProjectVersion;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 §8.7.5's seven selectors, resolved against the builds that exist.
 *
 * > "A project version MUST pin exactly one build per contributing
 * > component, and the reader-facing selector MUST expose **only project
 * > versions, never git refs**." (§8.7.4)
 *
 * That second clause is why this class exists at all. A reader choosing
 * "v2.3" from the flyout must not be choosing a branch of some contributing
 * repository, so something has to turn one project-level choice into one
 * build per component. This is that something, and §8.8.8 requires every
 * answer it gives to be written down.
 *
 * 🛑 **Candidates are successful builds only, and that is the exit
 * criterion.** §17 Phase 14: "A failed contributor build leaves the live
 * composition **intact and serving**." A failed build is not a candidate, so
 * a mount whose newest build failed resolves to the one before it and the
 * composition keeps serving — without a special case anywhere, because the
 * failure simply never entered the set.
 *
 * 🛑 **Nothing here reaches the network.** A selector resolves against
 * builds that already exist, never against a repository's current refs. The
 * difference shows up on the publish path: resolving `track_branch` by
 * asking the forge what `main` points at would make a publish depend on a
 * third party being up, and would name a commit no build exists for.
 */
final readonly class SelectorResolver
{
    /**
     * Resolve one mount against the builds of its component.
     *
     * @param  ProjectVersion  $version  the version being composed; its slug is
     *                                   what `mirror_label` mirrors
     * @param  Build|null  $justBuilt  🛑 the build this publish is about, which is
     *                                 not yet in a published state and so is not
     *                                 yet a candidate by query. Added to the set
     *                                 rather than forced onto its mount: a
     *                                 `pinned_build` mount must not move because
     *                                 something else built, and a `mirror_label`
     *                                 mount takes it only if its label matches.
     *                                 Forcing it would make every selector a lie
     *                                 on the one publish that matters most.
     */
    public function resolve(
        ComponentMount $mount,
        ProjectVersion $version,
        ?Build $justBuilt = null,
    ): SelectorResolution {
        $kind = $this->kindOf($mount);
        $value = $mount->selector_value;
        $fallback = $this->fallbackOf($mount);

        if ($kind->needsValue() && ($value === null || $value === '')) {
            return SelectorResolution::unresolved($kind, $value, $fallback, ResolutionOutcome::Misconfigured);
        }

        if ($kind === SelectorKind::PinnedBuild) {
            return $this->resolvePinnedBuild($mount, $kind, $value, $fallback);
        }

        $candidates = $this->candidatesFor($mount->component_id, $justBuilt);

        if ($candidates === []) {
            return SelectorResolution::unresolved($kind, $value, $fallback);
        }

        return match ($kind) {
            SelectorKind::LatestSuccess => $this->newest($candidates, $kind, $value, $fallback, ResolutionOutcome::LatestSuccess),
            SelectorKind::PinnedRef, SelectorKind::TrackBranch => $this->byRef($candidates, $kind, (string) $value, $fallback),
            SelectorKind::TrackTagPattern => $this->byPattern($candidates, $kind, (string) $value, $fallback),
            SelectorKind::TrackSemverRange => $this->byRange($candidates, $kind, (string) $value, $fallback),
            SelectorKind::LatestRelease => $this->latestRelease($candidates, $kind, $fallback),
            // `mirror_label` is all that is left: `pinned_build` returned
            // above, before the candidate set was ever built, because it
            // names bytes rather than a ref.
            default => $this->mirrorLabel($candidates, $kind, $fallback, $version),
        };
    }

    public function kindOf(ComponentMount $mount): SelectorKind
    {
        return SelectorKind::tryFrom($mount->selector_kind) ?? SelectorKind::LatestSuccess;
    }

    private function fallbackOf(ComponentMount $mount): ?MirrorFallback
    {
        $raw = $mount->mirror_fallback;

        return is_string($raw) ? MirrorFallback::tryFrom($raw) : null;
    }

    /**
     * 🛑 The one selector that does not read the candidate set.
     *
     * `pinned_build` names bytes, not a ref, so it is resolved by id and is
     * deliberately **not** filtered by state: §8.8.5 makes the previously
     * published build "intact and immediately re-selectable", and a
     * `success_unpublished` build is exactly the thing an operator pins when
     * they want the composition to stop moving. What it will not accept is
     * a build of a different component, which would let a mount serve
     * another component's bytes under this component's prefix.
     */
    private function resolvePinnedBuild(
        ComponentMount $mount,
        SelectorKind $kind,
        ?string $value,
        ?MirrorFallback $fallback,
    ): SelectorResolution {
        $buildId = is_string($value) ? Uuid::tryToBytes($value) : null;

        if ($buildId === null) {
            return SelectorResolution::unresolved($kind, $value, $fallback, ResolutionOutcome::Misconfigured);
        }

        $build = Build::query()
            ->whereKey($buildId)
            ->where('component_id', $mount->component_id)
            ->whereIn('state', ['published', 'success_unpublished'])
            ->first();

        if (! $build instanceof Build) {
            return SelectorResolution::unresolved($kind, $value, $fallback);
        }

        [$ref, $label] = $this->refAndLabel($build);

        return SelectorResolution::matched($kind, $value, $fallback, $build, $label, $ref, ResolutionOutcome::Pinned);
    }

    /**
     * Every successful build of a component, newest first.
     *
     * Ordered by `finished_at` and then by id. The id tiebreak is not
     * cosmetic: `finished_at` has millisecond precision and two builds of
     * one component completing in the same millisecond is ordinary on a
     * monorepo push, where a UUIDv7's own time ordering settles it.
     *
     * @param  string  $componentId  raw 16 bytes
     * @return list<Candidate>
     */
    private function candidatesFor(string $componentId, ?Build $justBuilt = null): array
    {
        /** @var list<Build> $builds */
        $builds = array_values(
            Build::query()
                ->where('component_id', $componentId)
                ->whereIn('state', ['published', 'success_unpublished'])
                ->orderByDesc('finished_at')
                ->orderByDesc('id')
                ->limit(self::CANDIDATE_LIMIT)
                ->get()
                ->all(),
        );

        if ($justBuilt instanceof Build && $justBuilt->component_id === $componentId) {
            $builds = array_values(array_filter(
                $builds,
                static fn (Build $build): bool => $build->id !== $justBuilt->id,
            ));

            // Newest, because it is the one finishing now. The query's own
            // ordering cannot place it: its `finished_at` is still null
            // until the compare-and-swap sets it.
            array_unshift($builds, $justBuilt);
        }

        if ($builds === []) {
            return [];
        }

        $refs = $this->refsFor(array_map(static fn (Build $build): string => $build->id, $builds));
        $sources = $this->sourcesFor($builds);
        $candidates = [];

        foreach ($builds as $build) {
            $ref = $refs[$build->id] ?? null;
            $sourceId = $build->component_source_id;
            $source = is_string($sourceId) ? ($sources[$sourceId] ?? null) : null;

            $candidates[] = new Candidate(
                build: $build,
                ref: $ref,
                label: $ref === null ? null : VersionLabel::from($source, $ref),
            );
        }

        return $candidates;
    }

    /**
     * 🛑 A ceiling on how far back a selector looks.
     *
     * Without one, a component with ten thousand builds loads ten thousand
     * rows on every publish of every project that mounts it — the cost
     * scaling with the component's history rather than with the
     * composition. A thousand is far beyond any real selector's reach: a
     * `track_branch` wants the newest, and `latest_release` wants the
     * highest label, which on any repository that releases is inside the
     * most recent thousand builds. The bound is stated here rather than
     * discovered as a slow publish.
     */
    private const CANDIDATE_LIMIT = 1000;

    /**
     * The ref each build was fetched from, by build id.
     *
     * 🛑 One query for the whole set rather than a relation per build.
     * `build_sources` is read here only for its `ref`, and the N+1 version
     * of this loop is the kind that is invisible until a project mounts
     * twelve components.
     *
     * @param  list<string>  $buildIds  raw 16 bytes each
     * @return array<string, string>
     */
    private function refsFor(array $buildIds): array
    {
        $rows = DB::table('build_sources')
            ->select(['build_id', 'ref'])
            ->whereIn('build_id', $buildIds)
            ->orderBy('id')
            ->get();

        $refs = [];

        foreach ($rows as $row) {
            $buildId = $row->build_id;
            $ref = $row->ref;

            if (! is_string($buildId) || ! is_string($ref)) {
                continue;
            }

            // First source wins. A distributed component [P2] has several,
            // and until §8.7.22 ships the first is the only one.
            $refs[$buildId] ??= $ref;
        }

        return $refs;
    }

    /**
     * The sources those builds came from, by id, for their label strategy.
     *
     * @param  list<Build>  $builds
     * @return array<string, ComponentSource>
     */
    private function sourcesFor(array $builds): array
    {
        $ids = [];

        foreach ($builds as $build) {
            $sourceId = $build->component_source_id;

            if (is_string($sourceId)) {
                $ids[$sourceId] = true;
            }
        }

        if ($ids === []) {
            return [];
        }

        $sources = [];

        foreach (ComponentSource::query()->whereIn('id', array_keys($ids))->get() as $source) {
            $sources[$source->id] = $source;
        }

        return $sources;
    }

    /**
     * @param  list<Candidate>  $candidates
     */
    private function newest(
        array $candidates,
        SelectorKind $kind,
        ?string $value,
        ?MirrorFallback $fallback,
        ResolutionOutcome $outcome,
    ): SelectorResolution {
        $first = $candidates[0];

        return SelectorResolution::matched($kind, $value, $fallback, $first->build, $first->label, $first->ref, $outcome);
    }

    /**
     * @param  list<Candidate>  $candidates
     */
    private function byRef(array $candidates, SelectorKind $kind, string $ref, ?MirrorFallback $fallback): SelectorResolution
    {
        foreach ($candidates as $candidate) {
            if ($candidate->ref === $ref) {
                return SelectorResolution::matched(
                    $kind, $ref, $fallback, $candidate->build, $candidate->label, $candidate->ref,
                    ResolutionOutcome::RefMatched,
                );
            }
        }

        return SelectorResolution::unresolved($kind, $ref, $fallback);
    }

    /**
     * Tags matching a glob, highest **label** wins.
     *
     * Highest label rather than newest build, because a repository that
     * back-ports to `v1.9` after releasing `v2.0` would otherwise have the
     * back-port win on recency — a selector written as "track my tags"
     * silently moving a project backwards.
     *
     * @param  list<Candidate>  $candidates
     */
    private function byPattern(array $candidates, SelectorKind $kind, string $glob, ?MirrorFallback $fallback): SelectorResolution
    {
        $matching = array_values(array_filter(
            $candidates,
            static fn (Candidate $candidate): bool => $candidate->ref !== null
                && PathGlob::anyMatches([$glob], [$candidate->ref]),
        ));

        if ($matching === []) {
            return SelectorResolution::unresolved($kind, $glob, $fallback);
        }

        $best = $this->highestLabelled($matching) ?? $matching[0];

        return SelectorResolution::matched(
            $kind, $glob, $fallback, $best->build, $best->label, $best->ref, ResolutionOutcome::PatternMatched,
        );
    }

    /**
     * @param  list<Candidate>  $candidates
     */
    private function byRange(array $candidates, SelectorKind $kind, string $range, ?MirrorFallback $fallback): SelectorResolution
    {
        $within = array_values(array_filter(
            $candidates,
            static fn (Candidate $candidate): bool => $candidate->version()?->satisfies($range) === true,
        ));

        if ($within === []) {
            return SelectorResolution::unresolved($kind, $range, $fallback);
        }

        $best = $this->highestLabelled($within) ?? $within[0];

        return SelectorResolution::matched(
            $kind, $range, $fallback, $best->build, $best->label, $best->ref, ResolutionOutcome::RangeMatched,
        );
    }

    /**
     * @param  list<Candidate>  $candidates
     */
    private function latestRelease(array $candidates, SelectorKind $kind, ?MirrorFallback $fallback): SelectorResolution
    {
        $stable = array_values(array_filter(
            $candidates,
            static fn (Candidate $candidate): bool => $candidate->version()?->isStable() === true,
        ));

        $best = $this->highestLabelled($stable);

        if (! $best instanceof Candidate) {
            return SelectorResolution::unresolved($kind, null, $fallback);
        }

        return SelectorResolution::matched(
            $kind, null, $fallback, $best->build, $best->label, $best->ref, ResolutionOutcome::ReleaseMatched,
        );
    }

    /**
     * 🛑 §8.7.5's worked example, implemented.
     *
     * > "project `v2.3` takes the glossary repository's `v2.0` because it is
     * > the highest label ≤ 2.3"
     *
     * The exact-label match is tried first and needs no fallback: a glossary
     * that does release `v2.3` serves `v2.3`. The fallback is what happens
     * when the cadences differ, and refusing to choose one — a mount with
     * `mirror_label` and no `mirror_fallback` — is
     * {@see ResolutionOutcome::Misconfigured} rather than a default, because
     * the three modes disagree in exactly the case that matters.
     *
     * @param  list<Candidate>  $candidates
     */
    private function mirrorLabel(
        array $candidates,
        SelectorKind $kind,
        ?MirrorFallback $fallback,
        ProjectVersion $version,
    ): SelectorResolution {
        if (! $fallback instanceof MirrorFallback) {
            return SelectorResolution::unresolved($kind, null, null, ResolutionOutcome::Misconfigured);
        }

        $wanted = $version->slug;
        $wantedVersion = SemanticVersion::parse($wanted);

        foreach ($candidates as $candidate) {
            if ($candidate->label === null) {
                continue;
            }

            $exact = $candidate->label === $wanted
                || ($wantedVersion instanceof SemanticVersion
                    && $candidate->version()?->compare($wantedVersion) === 0);

            if ($exact) {
                return SelectorResolution::matched(
                    $kind, $wanted, $fallback, $candidate->build, $candidate->label, $candidate->ref,
                    ResolutionOutcome::LabelMatched,
                );
            }
        }

        return match ($fallback) {
            MirrorFallback::Fail => SelectorResolution::unresolved(
                $kind, $wanted, $fallback, ResolutionOutcome::FallbackRefused,
            ),
            MirrorFallback::Newest => $this->newest(
                $candidates, $kind, $wanted, $fallback, ResolutionOutcome::FallbackNewest,
            ),
            MirrorFallback::NewestSemverLte => $this->newestSemverLte($candidates, $kind, $wanted, $wantedVersion),
        };
    }

    /**
     * @param  list<Candidate>  $candidates
     */
    private function newestSemverLte(
        array $candidates,
        SelectorKind $kind,
        string $wanted,
        ?SemanticVersion $ceiling,
    ): SelectorResolution {
        $fallback = MirrorFallback::NewestSemverLte;

        if (! $ceiling instanceof SemanticVersion) {
            /*
             * The project version's own slug is not a version — `latest`,
             * `stable`, `main`. There is no "≤" to compute against it, and
             * guessing would mean a channel version silently taking the
             * component's newest. §8.7.5's mode is named for an ordering
             * that does not exist here, so it does not resolve.
             */
            return SelectorResolution::unresolved($kind, $wanted, $fallback, ResolutionOutcome::NoCandidate);
        }

        $best = null;

        foreach ($candidates as $candidate) {
            $version = $candidate->version();

            if (! $version instanceof SemanticVersion || $version->compare($ceiling) > 0) {
                continue;
            }

            if ($best === null || $version->compare($best->version() ?? $version) > 0) {
                $best = $candidate;
            }
        }

        if (! $best instanceof Candidate) {
            return SelectorResolution::unresolved($kind, $wanted, $fallback);
        }

        return SelectorResolution::matched(
            $kind, $wanted, $fallback, $best->build, $best->label, $best->ref, ResolutionOutcome::FallbackSemverLte,
        );
    }

    /**
     * The candidate with the highest parseable label, or null if none has one.
     *
     * @param  list<Candidate>  $candidates
     */
    private function highestLabelled(array $candidates): ?Candidate
    {
        $best = null;
        $bestVersion = null;

        foreach ($candidates as $candidate) {
            $version = $candidate->version();

            if (! $version instanceof SemanticVersion) {
                continue;
            }

            if ($bestVersion === null || $version->compare($bestVersion) > 0) {
                $best = $candidate;
                $bestVersion = $version;
            }
        }

        return $best;
    }

    /** @return array{0: string|null, 1: string|null} */
    private function refAndLabel(Build $build): array
    {
        $refs = $this->refsFor([$build->id]);
        $ref = $refs[$build->id] ?? null;

        if ($ref === null) {
            return [null, null];
        }

        $sourceId = $build->component_source_id;
        $source = is_string($sourceId)
            ? ComponentSource::query()->whereKey($sourceId)->first()
            : null;

        return [$ref, VersionLabel::from($source, $ref)];
    }
}
