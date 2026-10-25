<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

/**
 * Which branch of a selector answered (§8.8.8's append-only record).
 *
 * Stored as a string on `mount_resolutions.outcome`, so a change here is a
 * change to recorded history's vocabulary rather than to a transient value.
 * Cases are added, never renamed.
 */
enum ResolutionOutcome: string
{
    /** `latest_success`: the newest successful build of the component. */
    case LatestSuccess = 'latest_success';

    /** `pinned_build`: the named build, which existed. */
    case Pinned = 'pinned';

    /** `pinned_ref` or `track_branch`: the newest build of that exact ref. */
    case RefMatched = 'ref_matched';

    /** `track_tag_pattern`: the highest-labelled build whose ref matched. */
    case PatternMatched = 'pattern_matched';

    /** `track_semver_range`: the highest label inside the range. */
    case RangeMatched = 'range_matched';

    /** `latest_release`: the highest stable label. */
    case ReleaseMatched = 'release_matched';

    /** `mirror_label`: the component carries the project version's own label. */
    case LabelMatched = 'label_matched';

    /** 🛑 `mirror_label` with `newest_semver_lte`: §8.7.5's worked example. */
    case FallbackSemverLte = 'fallback_semver_lte';

    /** `mirror_label` with `newest`: currency preferred to correspondence. */
    case FallbackNewest = 'fallback_newest';

    /** The selector was well formed and nothing matched it. */
    case NoCandidate = 'no_candidate';

    /**
     * The mount is misconfigured: a selector that needs a value and has
     * none, a `mirror_label` with no fallback, or a value that is not of
     * the shape the selector requires.
     *
     * Distinct from {@see self::NoCandidate} because the remedies differ —
     * one is "build something", the other is "fix the mount" — and a
     * publish that failed closed on a required mount should say which.
     */
    case Misconfigured = 'misconfigured';

    /** 🛑 `mirror_label` + `fail`: no exact label, and no fallback permitted. */
    case FallbackRefused = 'fallback_refused';
}
