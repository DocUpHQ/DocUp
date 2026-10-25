<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Composition;

use App\Composition\SelectorKind;
use App\Composition\SemanticVersion;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The ordering §8.7.5's three label-based selectors rest on.
 *
 * `track_semver_range`, `latest_release` and `mirror_label`'s
 * `newest_semver_lte` all reduce to "parse a label, order two of them", so
 * a mistake here is a project serving the wrong release of a contributing
 * repository — a failure that looks like correct behaviour until somebody
 * reads the page.
 */
final class SelectorSemanticsTest extends TestCase
{
    /**
     * 🛑 An unparseable label is **null**, never zero.
     *
     * A branch name sorting as 0.0.0 would win a `newest_semver_lte` race
     * against nothing and lose every other one — which is the quiet,
     * plausible wrong answer. Null keeps it out of the ordering entirely.
     */
    #[DataProvider('unparseableLabels')]
    public function test_a_label_that_is_not_a_version_does_not_parse(string $label): void
    {
        $this->assertNull(SemanticVersion::parse($label));
    }

    /** @return iterable<string, array{string}> */
    public static function unparseableLabels(): iterable
    {
        yield 'a branch' => ['main'];
        yield 'a release branch' => ['release/2.1'];
        yield 'empty' => [''];
        yield 'a v on its own' => ['v'];
        yield 'words' => ['stable'];
        yield 'a date' => ['2026-03-04'];
    }

    /** A partial version is a version: `v2` is what a great many tags say. */
    public function test_a_partial_version_parses_as_a_full_one(): void
    {
        $this->assertSame('2.0.0', (string) SemanticVersion::parse('v2'));
        $this->assertSame('2.1.0', (string) SemanticVersion::parse('2.1'));
        $this->assertSame('2.1.3', (string) SemanticVersion::parse('V2.1.3'));
    }

    /**
     * 🛑 SemVer 2.0.0 precedence, including the rule everybody forgets: a
     * prerelease sorts BELOW its own release.
     */
    #[DataProvider('orderings')]
    public function test_precedence(string $lower, string $higher): void
    {
        $a = SemanticVersion::parse($lower);
        $b = SemanticVersion::parse($higher);

        $this->assertInstanceOf(SemanticVersion::class, $a);
        $this->assertInstanceOf(SemanticVersion::class, $b);

        $this->assertSame(-1, $a->compare($b) <=> 0, $lower.' < '.$higher);
        $this->assertSame(1, $b->compare($a) <=> 0, $higher.' > '.$lower);
    }

    /** @return iterable<string, array{string, string}> */
    public static function orderings(): iterable
    {
        yield 'patch' => ['1.0.0', '1.0.1'];
        yield 'minor' => ['1.9.9', '1.10.0'];
        yield 'major' => ['1.99.0', '2.0.0'];
        yield 'prerelease below release' => ['2.0.0-rc.1', '2.0.0'];
        yield 'alpha below beta' => ['2.0.0-alpha', '2.0.0-beta'];
        yield 'shorter prerelease first' => ['2.0.0-alpha', '2.0.0-alpha.1'];
        yield 'numeric identifiers compare numerically' => ['2.0.0-rc.2', '2.0.0-rc.10'];
        yield 'numeric below alphanumeric' => ['2.0.0-1', '2.0.0-alpha'];
    }

    /** Build metadata is ignored for precedence, as SemVer 2.0.0 requires. */
    public function test_build_metadata_does_not_affect_precedence(): void
    {
        $plain = SemanticVersion::parse('1.2.3');
        $stamped = SemanticVersion::parse('1.2.3+20260304.abc');

        $this->assertInstanceOf(SemanticVersion::class, $plain);
        $this->assertInstanceOf(SemanticVersion::class, $stamped);
        $this->assertSame(0, $plain->compare($stamped));
    }

    #[DataProvider('ranges')]
    public function test_range_satisfaction(string $version, string $range, bool $expected): void
    {
        $parsed = SemanticVersion::parse($version);

        $this->assertInstanceOf(SemanticVersion::class, $parsed);
        $this->assertSame($expected, $parsed->satisfies($range), $version.' vs '.$range);
    }

    /** @return iterable<string, array{string, string, bool}> */
    public static function ranges(): iterable
    {
        yield 'exact' => ['2.1.0', '2.1.0', true];
        yield 'exact miss' => ['2.1.1', '2.1.0', false];
        yield 'conjunction' => ['2.5.0', '>=2.0.0 <3.0.0', true];
        yield 'conjunction upper bound' => ['3.0.0', '>=2.0.0 <3.0.0', false];
        yield 'disjunction' => ['1.9.0', '^1.0.0 || ^3.0.0', true];
        yield 'caret' => ['2.9.9', '^2.1.0', true];
        yield 'caret across major' => ['3.0.0', '^2.1.0', false];

        // 🛑 npm's zero-major rule: under 0.x the MINOR is the breaking axis.
        yield 'caret under zero major' => ['0.2.9', '^0.2.1', true];
        yield 'caret under zero major, next minor' => ['0.3.0', '^0.2.1', false];

        yield 'tilde' => ['2.1.9', '~2.1.0', true];
        yield 'tilde across minor' => ['2.2.0', '~2.1.0', false];

        // 🛑 A typo refuses rather than widening: a range nobody can parse
        // must not quietly match everything, because the result is a project
        // serving a contributing repository's unreleased work.
        yield 'a nonsense range matches nothing' => ['2.1.0', 'latest', false];
        yield 'an empty range matches nothing' => ['2.1.0', '', false];
    }

    /**
     * 🛑 Only `pinned_build` pins, and the distinction is §8.8.7's.
     *
     * "A release-kind version MUST rewrite every mount to `pinned_build` at
     * promotion, so a shipped release can never drift." A tag can be
     * force-pushed, so `pinned_ref` names a commit only until somebody
     * moves it — which makes it the wrong answer for a shipped release and
     * is exactly the week the difference shows up.
     */
    public function test_only_a_build_pin_is_immovable(): void
    {
        foreach (SelectorKind::cases() as $kind) {
            $this->assertSame(
                $kind === SelectorKind::PinnedBuild,
                $kind->pins(),
                $kind->value,
            );
        }
    }

    /** The three selectors whose question is complete without an argument. */
    public function test_which_selectors_need_a_value(): void
    {
        $needing = array_values(array_filter(
            SelectorKind::cases(),
            static fn (SelectorKind $kind): bool => $kind->needsValue(),
        ));

        $this->assertSame(
            ['pinned_build', 'pinned_ref', 'track_branch', 'track_tag_pattern', 'track_semver_range'],
            array_map(static fn (SelectorKind $kind): string => $kind->value, $needing),
        );
    }

    /** §8.7.5's seven, plus Phase 03's default, and nothing else. */
    public function test_the_selector_set_is_the_specified_one(): void
    {
        $this->assertSame(
            [
                'latest_success',
                'pinned_build',
                'pinned_ref',
                'track_branch',
                'track_tag_pattern',
                'track_semver_range',
                'latest_release',
                'mirror_label',
            ],
            SelectorKind::values(),
        );
    }
}
