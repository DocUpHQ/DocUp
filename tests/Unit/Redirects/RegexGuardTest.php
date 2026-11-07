<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Redirects;

use App\Redirects\RedirectRefused;
use App\Redirects\RedirectRejection;
use App\Redirects\RegexGuard;
use PHPUnit\Framework\TestCase;

/**
 * 🛑 §8.11.4's six controls, and §17's exit criterion: "A catastrophic-
 * backtracking regex is rejected by the linter."
 *
 * > "Regular-expression rules MUST be contained by a length cap (255), a
 * > nested-quantifier linter, a compile check, a lowered PCRE backtrack
 * > limit, a **fixed deterministic per-request evaluation cap** (20) and an
 * > installation-wide kill switch. A time-budget cap that silently skips
 * > rules under load makes redirect behaviour nondeterministic, which is
 * > worse than a fixed cap."
 *
 * 🛑 The last sentence is the one with a test of its own below, because it
 * is the design decision rather than a number: a fixed cap is the
 * requirement and a clock is the thing it refuses.
 */
final class RegexGuardTest extends TestCase
{
    /**
     * 🛑 The exit criterion, with the classic shapes.
     *
     * Each of these takes a 30-character pattern and a 40-character
     * non-matching input into billions of steps. They are refused at save
     * time, by shape, before they are ever compiled against input.
     */
    public function test_catastrophic_backtracking_is_refused_by_the_linter(): void
    {
        $catastrophic = [
            '/x/(a+)+$',
            '/x/(a*)*b',
            '/x/([a-z]+)+/',
            '/x/(\w{2,})+/',
            '/x/(a|aa)+$',
            '/x/(\d+|\d+\d)+/',
        ];

        foreach ($catastrophic as $pattern) {
            $this->assertNotNull(
                RegexGuard::nestedQuantifier($pattern),
                $pattern.' is catastrophic and the linter did not see it',
            );

            $this->assertRefused($pattern, RedirectRejection::RegexNestedQuantifier);
        }
    }

    /**
     * And an ordinary pattern is not refused.
     *
     * Without this the linter could satisfy the criterion by refusing
     * everything, which would meet the letter of §8.11.4 and remove the
     * feature.
     */
    public function test_ordinary_patterns_are_accepted(): void
    {
        $ordinary = [
            '/en/v2/rfc-(\d+)\.html',
            '/(en|ja)/v2/guide/(.*)',
            '/en/[^/]+/api/.*',
            '/docs/\d{4}/\d{2}/(.+)\.html',
        ];

        foreach ($ordinary as $pattern) {
            $this->assertNull(RegexGuard::nestedQuantifier($pattern), $pattern.' was flagged and is fine');
            RegexGuard::assertUsable($pattern);
        }

        $this->addToAssertionCount(count($ordinary));
    }

    /** §8.11.4's 255-byte cap. */
    public function test_an_overlong_pattern_is_refused(): void
    {
        $this->assertRefused('/'.str_repeat('a', 300), RedirectRejection::RegexTooLong);
    }

    /** §8.11.4's compile check. */
    public function test_an_uncompilable_pattern_is_refused(): void
    {
        $this->assertRefused('/en/(unclosed', RedirectRejection::RegexUncompilable);
    }

    /**
     * 🛑 §8.11.4's backtrack limit, measured rather than asserted from the
     * constant.
     *
     * The linter cannot catch every catastrophic pattern — recognising them
     * in general is undecidable — so the limit is what catches the rest.
     * This drives a pattern the linter deliberately misses and checks that
     * the match **returns quickly and reports no match** rather than
     * running for minutes.
     */
    public function test_the_backtrack_limit_bounds_a_pattern_the_linter_missed(): void
    {
        /*
         * No group at all, so the syntactic linter correctly ignores it —
         * and eight adjacent quantifiers over the same character make PCRE
         * explore O(n^8) partitions of a non-matching input. Polynomial
         * rather than exponential, which is exactly the class a linter
         * looking for nested quantifiers is not built to see.
         */
        $pattern = '/x*x*x*x*x*x*x*x*y';

        $this->assertNull(RegexGuard::nestedQuantifier($pattern), 'this test needs a pattern the linter misses');

        $started = hrtime(true);
        $result = RegexGuard::match($pattern, '/'.str_repeat('x', 40));
        $elapsed = (hrtime(true) - $started) / 1_000_000;

        $this->assertNull($result, 'a pattern that exceeded its budget has not matched');
        $this->assertLessThan(
            500.0,
            $elapsed,
            '🛑 the backtrack limit did not bite: '.round($elapsed).' ms on a 40-character input',
        );
    }

    /**
     * 🛑 Anchored at both ends.
     *
     * An unanchored redirect pattern matches a substring, so `/guide`
     * would fire on `/not-the-guide/page` — which is not what any operator
     * writing a redirect means, and is how a rule intended for one section
     * silently captures another.
     */
    public function test_patterns_are_anchored(): void
    {
        $this->assertNotNull(RegexGuard::match('/guide/.*', '/guide/page.html'));
        $this->assertNull(
            RegexGuard::match('/guide/.*', '/not-the-guide/page.html'),
            'an unanchored pattern would capture a section it was not written for',
        );
    }

    /**
     * 🛑 §8.11.4's cap is a **count**, not a clock, and this is the
     * assertion about that sentence.
     *
     * A time budget would make the same request behave differently under
     * load — a rule that fires on a quiet morning and not at noon, with a
     * reader getting a 404 an operator cannot reproduce. 20 is the same on
     * every replica on every request.
     */
    public function test_the_evaluation_cap_is_a_fixed_count(): void
    {
        $this->assertSame(20, RegexGuard::MAX_EVALUATIONS_PER_REQUEST);
        $this->assertIsInt(RegexGuard::MAX_EVALUATIONS_PER_REQUEST);

        $source = (string) file_get_contents(dirname(__DIR__, 3).'/app/Redirects/RedirectEngine.php');

        foreach (['microtime', 'hrtime', 'time()', 'Carbon'] as $clock) {
            $this->assertStringNotContainsString(
                $clock,
                $source,
                '🛑 the engine must not consult a clock: §8.11.4 refuses a time budget by name',
            );
        }
    }

    private function assertRefused(string $pattern, RedirectRejection $expected): void
    {
        try {
            RegexGuard::assertUsable($pattern);
        } catch (RedirectRefused $refused) {
            $this->assertSame($expected, $refused->rejection, 'wrong refusal for "'.$pattern.'"');

            return;
        }

        $this->fail('"'.$pattern.'" was accepted and should have been refused');
    }
}
