<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Versions;

use App\Versions\VersionComparator;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * §8.6.4's comparator, and the exit criterion that names it by example.
 *
 * > "`v1.10` sorts above `v1.9` under the `semver` comparator and below it
 * > under `alphabetical`, proving the comparator is wired."
 *
 * 🛑 **Both directions, because one alone proves nothing.** A comparator
 * that always sorted numerically would pass the first half; one that always
 * sorted by string would pass the second. Only the pair shows that the
 * project's setting is being read — which is what "proving the comparator is
 * wired" asks for.
 */
final class VersionComparatorTest extends TestCase
{
    /** 🛑 The exit criterion, verbatim, in both directions. */
    public function test_v1_10_sorts_above_v1_9_under_semver_and_below_it_under_alphabetical(): void
    {
        $refs = ['v1.9', 'v1.10'];

        $this->assertSame(
            ['v1.10', 'v1.9'],
            VersionComparator::Semver->descending($refs),
            'v1.10 must sort above v1.9 under semver (§8.6.5: the first bug report every installation receives)',
        );

        $this->assertSame(
            ['v1.9', 'v1.10'],
            VersionComparator::Alphabetical->descending($refs),
            'and below it under alphabetical, which is what proves the setting is read',
        );
    }

    /**
     * @param  list<string>  $refs
     * @param  list<string>  $expected
     */
    #[DataProvider('semverOrders')]
    public function test_semver_orders_as_the_specification_does(array $refs, array $expected): void
    {
        $this->assertSame($expected, VersionComparator::Semver->descending($refs));
    }

    /** @return iterable<string, array{list<string>, list<string>}> */
    public static function semverOrders(): iterable
    {
        yield 'numeric components, not strings' => [
            ['v1.2.3', 'v1.2.10', 'v1.10.0', 'v1.9.9'],
            ['v1.10.0', 'v1.9.9', 'v1.2.10', 'v1.2.3'],
        ];

        yield 'a prerelease is older than its release' => [
            ['v2.0.0', 'v2.0.0-rc1', 'v2.0.0-alpha'],
            ['v2.0.0', 'v2.0.0-rc1', 'v2.0.0-alpha'],
        ];

        yield 'prerelease identifiers compare left to right' => [
            ['1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta'],
            ['1.0.0-beta', '1.0.0-alpha.beta', '1.0.0-alpha.1', '1.0.0-alpha'],
        ];

        yield 'a missing patch is zero, not lower' => [
            ['v1.2', 'v1.2.0', 'v1.2.1'],
            ['v1.2.1', 'v1.2', 'v1.2.0'],
        ];

        yield 'build metadata is ignored' => [
            ['1.0.0+build.2', '1.0.1'],
            ['1.0.1', '1.0.0+build.2'],
        ];

        // 🛑 A ref the comparator cannot read sorts below every ref it can.
        // Without this a branch called `feature/login` could win §8.6.4's
        // "highest branch" step and become `stable`.
        yield 'an unreadable ref sorts below every readable one' => [
            ['v1.0.0', 'feature-login', 'v0.1.0'],
            ['v1.0.0', 'v0.1.0', 'feature-login'],
        ];
    }

    /**
     * 🛑 PEP 440's two traps, which §8.6.4 names: `1.0rc1` and `1.0.post1`.
     *
     * `.post` is a RELEASE and is newer than the version it follows; `rc` is
     * a prerelease and is older. Getting them the same way round is the
     * specific failure that sentence is about.
     */
    public function test_pep440_places_post_after_the_release_and_rc_before_it(): void
    {
        $this->assertSame(
            ['1.0.post1', '1.0', '1.0rc1', '1.0b1', '1.0a1', '1.0.dev1'],
            VersionComparator::Pep440->descending(
                ['1.0', '1.0rc1', '1.0.post1', '1.0a1', '1.0b1', '1.0.dev1'],
            ),
        );
    }

    public function test_pep440_honours_an_epoch(): void
    {
        $this->assertSame(
            ['1!1.0', '2.0'],
            VersionComparator::Pep440->descending(['2.0', '1!1.0']),
        );
    }

    public function test_calver_sorts_by_date(): void
    {
        $this->assertSame(
            ['2026.10.24', '2026.10.2', '2026.9.30', '2025.12.31'],
            VersionComparator::Calver->descending(['2026.9.30', '2026.10.24', '2025.12.31', '2026.10.2']),
        );
    }

    /**
     * 🛑 §8.6.4: "the highest **tag** by the project's configured
     * comparator, **prereleases excluded**".
     *
     * A project that tags `v2.0.0-rc1` and finds `stable` pointing at it has
     * shipped a release candidate to every reader who did not pick a version.
     */
    public function test_prereleases_are_excluded_from_the_highest(): void
    {
        $refs = ['v1.0.0', 'v2.0.0-rc1'];

        $this->assertSame('v2.0.0-rc1', VersionComparator::Semver->highest($refs));
        $this->assertSame('v1.0.0', VersionComparator::Semver->highest($refs, excludePrereleases: true));
    }

    /**
     * 🛑 §8.6.4's step 5: "no `stable` at all, which is a valid state and
     * MUST NOT fall back to the default branch."
     *
     * A set the comparator cannot read must yield null rather than its first
     * or lowest member, or a project with no release tags gets a `stable`
     * pointing at whatever branch happened to sort lowest.
     */
    public function test_a_set_with_nothing_readable_has_no_highest(): void
    {
        $this->assertNull(VersionComparator::Semver->highest(['main', 'develop', 'feature-login']));
        $this->assertNull(VersionComparator::Semver->highest([]));

        // The control: alphabetical reads everything, so it always answers.
        $this->assertSame('main', VersionComparator::Alphabetical->highest(['main', 'develop']));
    }

    /** An unknown stored value yields the default rather than throwing. */
    public function test_an_unknown_comparator_falls_back_to_semver(): void
    {
        $this->assertSame(VersionComparator::Semver, VersionComparator::fromStored(null));
        $this->assertSame(VersionComparator::Semver, VersionComparator::fromStored('nonsense'));
        $this->assertSame(VersionComparator::Calver, VersionComparator::fromStored('calver'));
    }

    /**
     * Equal versions break ties by name, so a sort is total.
     *
     * Without this `v1.0` and `v1.0.0` come back in whatever order the
     * caller passed them, and a flyout re-sorted on each page load flickers
     * between two orderings.
     */
    public function test_the_order_is_total(): void
    {
        $this->assertSame(
            ['v1.0', 'v1.0.0'],
            VersionComparator::Semver->descending(['v1.0.0', 'v1.0']),
        );

        $this->assertSame(
            ['v1.0', 'v1.0.0'],
            VersionComparator::Semver->descending(['v1.0', 'v1.0.0']),
        );
    }
}
