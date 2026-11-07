<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Redirects;

use App\Redirects\RedirectEngine;
use App\Redirects\RedirectSet;
use App\Redirects\UrlCases;
use PHPUnit\Framework\TestCase;

/**
 * 🛑 §17's Phase 20 exit criterion: "A documented table of **twelve URL
 * cases** each produce the specified status and `Location`."
 *
 * The table is {@see UrlCases}, which is also what the operator guide
 * renders — so this test and the documentation cannot disagree. Phase 17
 * found the cost of the alternative: §8.7.13's mode matrix was prose that
 * had drifted from the code, and the fix was to generate it.
 *
 * 🛑 Unit, not feature, and that is a property of the engine rather than a
 * shortcut. §8.11.4 requires "a **fixed deterministic** per-request
 * evaluation cap", determinism is a property of a function, and
 * {@see RedirectEngine} is one — no database, no cache, no clock. Twelve
 * HTTP round trips would prove the same twelve facts more slowly and less
 * exactly.
 */
final class UrlCasesTest extends TestCase
{
    /** All twelve, each named in the failure message by its own number. */
    public function test_the_twelve_documented_cases_produce_the_documented_answers(): void
    {
        $engine = new RedirectEngine;
        $set = new RedirectSet(UrlCases::rules(), regexEnabled: true);

        foreach (UrlCases::cases() as $case) {
            [$language, $version] = $this->segmentsOf($case['path']);

            /*
             * Both passes, in §8.11.1's order: forced first, then unforced
             * once the existence probe has failed. The table's cases are
             * about paths that name nothing except case 1, which is the
             * forced one — so running both and taking the first answer is
             * the same sequence the controller performs.
             */
            $match = $engine->follow($set, $case['path'], $language, $version, forced: true)
                ?? $engine->follow($set, $case['path'], $language, $version, forced: false);

            $where = 'case '.$case['case'].' ('.$case['clause'].', '.$case['path'].')';

            if ($case['status'] === null) {
                $this->assertNull($match, $where.' must match no rule: '.$case['note']);

                continue;
            }

            $this->assertNotNull($match, $where.' matched nothing');
            $this->assertSame($case['status'], $match->status, $where.' status');
            $this->assertSame($case['location'], $match->to, $where.' Location');
            $this->assertSame($case['rule'], $match->rule, $where.' rule');
        }
    }

    /** Twelve, and the count is the criterion rather than an accident. */
    public function test_there_are_twelve_cases(): void
    {
        $this->assertCount(12, UrlCases::cases());
    }

    /**
     * 🛑 Every mechanism §8.11.2 names has a case.
     *
     * Without this, twelve cases could all exercise `exact` and the table
     * would satisfy the exit criterion's arithmetic and none of its
     * purpose.
     */
    public function test_every_rule_type_and_every_status_appears(): void
    {
        $clauses = array_column(UrlCases::cases(), 'clause');
        $statuses = array_filter(array_column(UrlCases::cases(), 'status'));

        foreach (['prefix', 'version-agnostic', 'clean URL', 'regex', 'forced', 'chain', 'absence'] as $mechanism) {
            $this->assertTrue(
                array_any($clauses, static fn (string $clause): bool => str_contains($clause, $mechanism)),
                'no documented case demonstrates '.$mechanism,
            );
        }

        foreach ([301, 302, 307, 308] as $status) {
            $this->assertContains($status, $statuses, 'no documented case produces '.$status);
        }
    }

    /** And the rendered table has a row per case, so the guide cannot lag. */
    public function test_the_markdown_table_has_a_row_for_every_case(): void
    {
        $markdown = UrlCases::toMarkdown();

        foreach (UrlCases::cases() as $case) {
            $this->assertStringContainsString('`'.$case['path'].'`', $markdown, 'case '.$case['case']);
        }

        // Header, separator, twelve rows.
        $this->assertCount(14, array_filter(explode("\n", trim($markdown))));
    }

    /**
     * The language and version a request carries, for the version-agnostic
     * rules.
     *
     * @return array{0: string, 1: string}
     */
    private function segmentsOf(string $path): array
    {
        $parts = explode('/', trim($path, '/'));

        return [$parts[0], $parts[1] ?? ''];
    }
}
