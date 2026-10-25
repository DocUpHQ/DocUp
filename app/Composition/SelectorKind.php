<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

/**
 * §8.7.5's per-mount version selectors.
 *
 * > "Per-mount version selectors MUST include `pinned_build`, `pinned_ref`,
 * > `track_branch`, `track_tag_pattern`, `track_semver_range`,
 * > `latest_release` and `mirror_label`."
 *
 * Eight cases for seven selectors: {@see self::LatestSuccess} is Phase 03's
 * default and means "whatever built last". §8.7.5 lists what a project
 * composing several repositories needs; it does not require the trivial
 * single-repository case to choose one of them, and making it choose would
 * mean every new project picked a tracking strategy before it had anything
 * to track.
 *
 * 🛑 **The division that matters is {@see self::pins()}.** A pinned selector
 * cannot move on its own: it names a build or a commit, and the same mount
 * resolves to the same bytes forever. Everything else is a *tracking*
 * selector, whose answer changes when the repository changes — which is
 * exactly what §8.8.7 forbids a shipped release from doing, and why
 * promotion rewrites every mount to `pinned_build`.
 */
enum SelectorKind: string
{
    /** Whatever built last and succeeded. The degenerate default. */
    case LatestSuccess = 'latest_success';

    /** A specific build, by id. Immovable. */
    case PinnedBuild = 'pinned_build';

    /** A specific ref, by exact name. The newest successful build of it. */
    case PinnedRef = 'pinned_ref';

    /** A branch, followed. */
    case TrackBranch = 'track_branch';

    /** Tags matching a glob, highest version label wins. */
    case TrackTagPattern = 'track_tag_pattern';

    /** Version labels inside a semantic-version range. */
    case TrackSemverRange = 'track_semver_range';

    /** The highest stable version label, prereleases excluded. */
    case LatestRelease = 'latest_release';

    /**
     * 🛑 The one §8.7.5 argues for at length: the component's build whose
     * version label mirrors the *project version's* own slug, with a
     * fallback when the contributing repository releases on a different
     * cadence.
     */
    case MirrorLabel = 'mirror_label';

    /**
     * Whether this selector names an immovable target (§8.8.7).
     *
     * `pinned_ref` is **not** pinned by this definition, and the distinction
     * is the point: a tag can be force-pushed and a ref therefore names a
     * commit only until someone moves it. §8.8.7's "a shipped release can
     * never drift" is satisfied only by `pinned_build`, which names bytes
     * that already exist.
     */
    public function pins(): bool
    {
        return $this === self::PinnedBuild;
    }

    /** Whether {@see MirrorFallback} applies, i.e. this is `mirror_label`. */
    public function usesFallback(): bool
    {
        return $this === self::MirrorLabel;
    }

    /**
     * Whether `selector_value` must be present.
     *
     * The three that need nothing are the ones whose question is complete
     * without an argument: "the last success", "the highest release", and
     * "the label this project version already has".
     */
    public function needsValue(): bool
    {
        return match ($this) {
            self::LatestSuccess, self::LatestRelease, self::MirrorLabel => false,
            default => true,
        };
    }

    /** @return list<string> */
    public static function values(): array
    {
        return array_map(static fn (self $kind): string => $kind->value, self::cases());
    }
}
