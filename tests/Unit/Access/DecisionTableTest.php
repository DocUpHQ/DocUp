<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Access;

use App\Access\AccessReason;
use App\Access\AccessSurface;
use App\Access\DecisionTable;
use App\Access\EffectiveAccess;
use PHPUnit\Framework\TestCase;

/**
 * 🛑 §17's Phase 21 exit criterion, and §12.3's "generated exhaustive decision
 * table":
 *
 * > "The full matrix — `{public, private} × {active, hidden} × {member,
 * > non-member, anonymous} × {proxy, download, search, addons}` — asserted at
 * > **100%**."
 *
 * The table is {@see DecisionTable}, which is also what the operator guide
 * renders — so this test and the documentation cannot disagree. Phase 17 found
 * the cost of the alternative: §8.7.13's mode matrix was prose that had drifted
 * from the code, and the fix was to generate it.
 *
 * 🛑 Unit, not feature, and that is a property of the subject rather than a
 * shortcut. §12.3 requires `EffectiveAccess` to be **pure**, purity is a
 * property of a function, and 48 HTTP round trips would prove the same 48 facts
 * more slowly and less exactly — they would also be unable to assert the two
 * axes whose whole content is that they change *nothing*.
 */
final class DecisionTableTest extends TestCase
{
    /** 🛑 All 48, each named in the failure message by its own number. */
    public function test_the_full_matrix_is_asserted(): void
    {
        foreach (DecisionTable::cases() as $case) {
            $decision = EffectiveAccess::decide(DecisionTable::requestFor($case));

            $where = sprintf(
                'case %d (%s version, %s, %s, %s)',
                $case['case'],
                $case['visibility'],
                $case['listed'],
                $case['reader'],
                $case['surface']->value,
            );

            $this->assertSame($case['allowed'], $decision->allowed, $where.' allowed');
            $this->assertSame($case['status'], $decision->status, $where.' status');
            $this->assertSame($case['reason'], $decision->reason, $where.' reason');
            $this->assertSame(
                $case['publicly_cacheable'],
                $decision->rulePubliclyCacheable,
                $where.' public cacheability',
            );
        }
    }

    /**
     * 🛑 48, and the count is the criterion rather than an accident.
     *
     * 2 × 2 × 3 × 4. Asserted so that adding a fifth surface or a fifth lattice
     * level cannot silently leave the matrix partial — the number moves, this
     * fails, and whoever added the axis has to state the new expectations.
     */
    public function test_there_are_forty_eight_cases(): void
    {
        $this->assertCount(48, DecisionTable::cases());
        $this->assertCount(4, AccessSurface::cases(), '§8.12.21 names four surfaces');
    }

    /**
     * 🛑 §8.6.2: "`hidden` is not `private`." The `listed` axis changes no
     * authorisation answer.
     *
     * > "Version visibility MUST be modelled as **four independent axes** —
     * > `active`, `listed`, `published` and `visibility` — which MUST NOT be
     * > collapsed or derived from one another, with a test proving their
     * > independence."
     *
     * This is that proof on the authorisation side. A hidden version "serves by
     * direct URL and is absent from the flyout, sitemap, `llms.txt` and
     * search", so a decision that consulted `listed` would have collapsed two
     * of the four axes — and the symptom would be a 404 on a URL somebody was
     * deliberately given.
     */
    public function test_the_listed_axis_changes_no_decision(): void
    {
        $byShape = [];

        foreach (DecisionTable::cases() as $case) {
            $decision = EffectiveAccess::decide(DecisionTable::requestFor($case));

            // Everything except `listed`, so the two listed values collide.
            $shape = $case['visibility'].'|'.$case['reader'].'|'.$case['surface']->value;

            $answer = ($decision->allowed ? 'allow' : 'deny').':'.$decision->status;

            if (isset($byShape[$shape])) {
                $this->assertSame(
                    $byShape[$shape],
                    $answer,
                    '🛑 §8.6.2: `listed` changed the decision for '.$shape,
                );

                continue;
            }

            $byShape[$shape] = $answer;
        }

        $this->assertCount(24, $byShape, 'every shape must appear twice, once per listed value');
    }

    /**
     * 🛑 The exit criterion's own sentence: "A private version 404s
     * anonymously, 200s for a member."
     *
     * Named separately from the matrix because it is the sentence an operator
     * reads, and a test whose name is the requirement is the one that survives
     * a refactor.
     */
    public function test_a_private_version_404s_anonymously_and_200s_for_a_member(): void
    {
        $cases = DecisionTable::cases();

        $anonymous = $this->find($cases, 'private', 'anonymous', AccessSurface::Proxy);
        $member = $this->find($cases, 'private', 'member', AccessSurface::Proxy);

        $this->assertSame(404, EffectiveAccess::decide(DecisionTable::requestFor($anonymous))->status);
        $this->assertTrue(EffectiveAccess::decide(DecisionTable::requestFor($member))->allowed);
        $this->assertSame(200, EffectiveAccess::decide(DecisionTable::requestFor($member))->status);
    }

    /**
     * 🛑 And the middle rung is real: an authenticated **non-member** is
     * refused a `members` version.
     *
     * Without this the matrix would pass against an implementation that had
     * only "signed in" and "not signed in" — and §12.3's four-value lattice
     * would be three values and a label.
     */
    public function test_an_authenticated_non_member_is_refused_a_members_version(): void
    {
        $case = $this->find(DecisionTable::cases(), 'private', 'non-member', AccessSurface::Proxy);
        $decision = EffectiveAccess::decide(DecisionTable::requestFor($case));

        $this->assertFalse($decision->allowed);
        $this->assertSame(AccessReason::VersionVisibility, $decision->reason);
        $this->assertSame(404, $decision->status, '§8.12.23: 404 unless the project configured 403');
    }

    /** The rendered table has a row per case, so the guide cannot lag. */
    public function test_the_markdown_table_has_a_row_for_every_case(): void
    {
        $markdown = DecisionTable::toMarkdown();

        // Header, separator, 48 rows.
        $this->assertCount(50, array_filter(explode("\n", trim($markdown))));

        foreach (DecisionTable::cases() as $case) {
            $this->assertStringContainsString('| '.$case['case'].' | ', $markdown, 'case '.$case['case']);
        }
    }

    /**
     * @param  list<array{case: int, visibility: string, listed: string, reader: string, surface: AccessSurface, allowed: bool, status: int, reason: AccessReason, publicly_cacheable: bool}>  $cases
     * @return array{case: int, visibility: string, listed: string, reader: string, surface: AccessSurface, allowed: bool, status: int, reason: AccessReason, publicly_cacheable: bool}
     */
    private function find(array $cases, string $visibility, string $reader, AccessSurface $surface): array
    {
        foreach ($cases as $case) {
            if ($case['visibility'] === $visibility
                && $case['reader'] === $reader
                && $case['surface'] === $surface
                && $case['listed'] === 'active') {
                return $case;
            }
        }

        $this->fail('no case for '.$visibility.'/'.$reader.'/'.$surface->value);
    }
}
