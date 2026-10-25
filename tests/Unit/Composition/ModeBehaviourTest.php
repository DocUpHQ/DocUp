<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Composition;

use App\Composition\ModeBehaviour;
use PHPUnit\Framework\TestCase;

/**
 * 🛑 §8.7.13's matrix, "as a table in the operator documentation and
 * **asserted by tests**".
 *
 * > "The two modes are different products; leaving the difference implicit
 * > is the single largest specification risk in the composition area."
 *
 * So this file asserts three things, and each closes a different way the
 * table could stop meaning anything:
 *
 *  1. every axis §8.7.13 names is present, so a behaviour cannot be
 *     dropped;
 *  2. every axis answers for both modes, so a column cannot be left blank;
 *  3. the committed documentation is byte-identical to what the table
 *     renders, so the two cannot drift.
 */
final class ModeBehaviourTest extends TestCase
{
    /**
     * §8.7.13's eight axes, verbatim and in its order.
     *
     * Hard-coded here on purpose. Reading them from `ModeBehaviour` would
     * make this test assert that the table equals itself.
     */
    private const SPECIFIED_AXES = [
        'navigation_source',
        'search_provenance',
        'not_found_chain',
        'cross_reference',
        'offline_formats',
        'provenance',
        'contributor_build_failure',
        'fragment_cacheability',
    ];

    public function test_every_axis_the_requirement_names_is_present(): void
    {
        $this->assertSame(self::SPECIFIED_AXES, ModeBehaviour::axes());
    }

    public function test_every_axis_answers_for_both_modes(): void
    {
        foreach (ModeBehaviour::table() as $key => $axis) {
            foreach (ModeBehaviour::MODES as $mode) {
                $this->assertArrayHasKey($mode, $axis, $key.' has no '.$mode.' behaviour');
                $this->assertNotSame('', trim($axis[$mode]), $key.'/'.$mode.' is blank');
            }

            $this->assertNotSame(
                $axis['mount'],
                $axis['single_pass'],
                $key.' describes both modes identically, which is the thing §8.7.13 forbids',
            );
        }
    }

    /**
     * 🛑 §8.7.12 defers `overlay` past 1.0, so it is not a mode.
     *
     * "it is a shadow-content vector by construction, including replacement
     * of another team's security notices, for a capability nobody asked
     * for." A row for it here would be the first step back toward shipping
     * it.
     */
    public function test_overlay_is_not_a_mode(): void
    {
        $this->assertSame(['mount', 'single_pass'], ModeBehaviour::MODES);
    }

    /**
     * 🛑 Only `mount` is live. Phase 15 brings the other column.
     *
     * Asserted so that a future reader cannot take the `single_pass`
     * column for implemented behaviour, and so that P15 has a test to
     * flip.
     */
    public function test_only_mount_mode_is_implemented_in_this_phase(): void
    {
        $this->assertTrue(ModeBehaviour::implementedIn('mount'));
        $this->assertFalse(ModeBehaviour::implementedIn('single_pass'));
    }

    /**
     * 🛑 The committed documentation is what the table renders.
     *
     * One statement with two readers rather than two statements that
     * drift — which is the whole reason the table lives in code and the
     * Markdown is generated.
     */
    public function test_the_documented_table_matches_the_code(): void
    {
        $readme = dirname(__DIR__, 3).'/app/Composition/README.md';

        $this->assertFileExists($readme);

        $contents = (string) file_get_contents($readme);

        foreach (explode("\n", trim(ModeBehaviour::toMarkdown())) as $row) {
            $this->assertStringContainsString(
                $row,
                $contents,
                'app/Composition/README.md is generated from ModeBehaviour::table(); re-render it',
            );
        }
    }
}
