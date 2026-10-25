<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

use App\Builds\SafePattern;
use App\Models\ComponentSource;

/**
 * §10.2's `version_label_strategy`, applied.
 *
 * A component's builds are identified to a selector by their **label**, not
 * by their ref: `mirror_label` compares a project version's slug against
 * them, `latest_release` orders them, and `track_semver_range` filters them.
 * The label comes from the ref through one of §10.2's three strategies, and
 * the strategy is a property of the **source** — because the same component
 * moved from a repository that tags `v2.1` to one that tags `release/2.1`
 * must keep producing the same labels.
 *
 * 🛑 A strategy that produces nothing returns null rather than the ref. The
 * difference matters for `semver_from_tag`: a build of `main` has no version
 * label, and labelling it `main` would put a branch into an ordering where
 * the next comparison silently treats it as unparseable — the same outcome,
 * reached one step later and one step less obviously.
 */
final readonly class VersionLabel
{
    /**
     * Derive the label of a build from the ref it was built from.
     *
     * @param  string  $ref  unqualified, as `build_sources.ref` stores it
     */
    public static function from(?ComponentSource $source, string $ref): ?string
    {
        if (! $source instanceof ComponentSource) {
            // No source: the component was published directly, so the ref is
            // the only label there can be.
            return $ref === '' ? null : $ref;
        }

        return match ($source->version_label_strategy) {
            'semver_from_tag' => self::semverFromTag($ref),
            'regex' => self::byRegex($ref, $source->version_label_regex),
            default => $ref === '' ? null : $ref,
        };
    }

    /**
     * The semantic version a tag names, normalised.
     *
     * Normalised rather than echoed, so `v2.1` and `2.1.0` from two
     * repositories produce one label and `mirror_label` can match across
     * them. That is the whole reason this strategy exists: §8.7.5's example
     * is a project at `v2.3` reading a glossary at `v2.0`, and the two
     * repositories are allowed to disagree about the leading `v`.
     */
    private static function semverFromTag(string $ref): ?string
    {
        $version = SemanticVersion::parse($ref);

        return $version instanceof SemanticVersion ? (string) $version : null;
    }

    /**
     * The first capture group of an operator-supplied pattern.
     *
     * 🛑 Run through {@see SafePattern} rather than `preg_match` directly:
     * the pattern is operator-written and a catastrophically backtracking
     * one would stall the publish path. The guard already exists for
     * §8.5.4's path filters and this is the same class of input.
     */
    private static function byRegex(string $ref, ?string $pattern): ?string
    {
        if ($pattern === null || $pattern === '') {
            return null;
        }

        $captured = SafePattern::firstGroup($pattern, $ref);

        return $captured === null || $captured === '' ? null : $captured;
    }
}
