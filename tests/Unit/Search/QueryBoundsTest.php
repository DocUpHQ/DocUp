<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Search;

use App\Search\QueryParser;
use App\Search\SearchRanking;
use PHPUnit\Framework\TestCase;

/**
 * 🛑 The bounds and the fail-closed branches the mutation gate found unasserted.
 *
 * §9.4 puts a mutation score on changed domain code for security-critical
 * phases, and the reason is this file. The first measurement of
 * {@see QueryParser} and {@see SearchRanking} reported 85.96% — above §9.4's
 * 75% floor — and every surviving mutation was a **behavioural rule with no
 * test**, exactly as Phase 28 found for `ChromeInjector`:
 *
 *  - `MAX_QUERY_LENGTH` and `MAX_TERMS` could be moved freely, or their
 *    comparisons flipped. `QueryParserTest` asserts that a long query is
 *    *bounded*, which is true for any bound.
 *  - A scope prefix's case-insensitivity and the slug's lowercasing could be
 *    removed. `project:docup` was tested; `PROJECT:DocUp` was not.
 *  - `SearchRanking::fromConfig(null)`'s short circuit could become an `&&`.
 *  - `ignore:` holding something that is **not** a list could silently bring
 *    the Read the Docs defaults back.
 *  - A pattern that normalises to nothing could be stored rather than skipped.
 *
 * Each of those is a real difference in what a reader's query does or what an
 * author's configuration means. Being above the floor was not the same as
 * having tested them, which is the whole argument for the gate.
 */
final class QueryBoundsTest extends TestCase
{
    private QueryParser $parser;

    protected function setUp(): void
    {
        parent::setUp();

        $this->parser = new QueryParser;
    }

    /**
     * 🛑 The query-length bound, at the boundary.
     *
     * Asserted as a **pair** — one character under is untouched, one over is
     * cut — because either half alone is satisfied by a bound anywhere nearby.
     * The cap exists so that every loop in the parser is bounded by a constant
     * rather than by the request, and a cap that had quietly moved would still
     * look like a cap.
     */
    public function test_the_query_length_bound_is_exact(): void
    {
        $exact = str_repeat('a', QueryParser::MAX_QUERY_LENGTH);

        /*
         * One term, because the string is one word: the assertion is on its
         * LENGTH, which `MAX_TERM_LENGTH` then caps separately — so the term is
         * compared against the smaller of the two, and the query-length bound
         * is observed through `raw` staying whole.
         */
        $this->assertSame($exact, $this->parser->parse($exact)->raw);

        /*
         * One character over, as a space-separated pair so the truncation is
         * observable in the TERMS rather than only in the raw string: the last
         * character of the second word is what the cap removes.
         */
        $over = str_repeat('a', QueryParser::MAX_QUERY_LENGTH - 2).' bc';

        $this->assertSame(
            QueryParser::MAX_QUERY_LENGTH + 1,
            mb_strlen($over),
            'the fixture is one character over the cap',
        );

        $parsed = $this->parser->parse($over);

        $this->assertSame(
            ['b'],
            array_slice($parsed->terms, 1),
            'the character past the cap is gone, so `bc` arrives as `b`',
        );
    }

    /**
     * 🛑 The term cap counts terms **and** phrases, and the comparison is `<`.
     *
     * The cap is `count($phrases) + count($terms) < MAX_TERMS`, which means a
     * query of fifteen terms and five phrases keeps sixteen things in total and
     * not twenty. Asserted on a mixture, because the two branches are separate
     * `if`s and a test over terms alone leaves the phrase branch unmeasured.
     */
    public function test_the_term_cap_counts_terms_and_phrases_together(): void
    {
        $terms = implode(' ', array_fill(0, QueryParser::MAX_TERMS, 'word'));
        $phrases = implode(' ', array_fill(0, 5, '"a phrase"'));

        $parsed = $this->parser->parse($terms.' '.$phrases);

        $this->assertSame(
            QueryParser::MAX_TERMS,
            count($parsed->terms) + count($parsed->phrases),
            'the cap is on the total, not on each kind',
        );

        /* And the other way round, so the phrase branch is the one that fills it. */
        $phraseFirst = $this->parser->parse(
            implode(' ', array_fill(0, QueryParser::MAX_TERMS + 4, '"a phrase"')),
        );

        $this->assertCount(QueryParser::MAX_TERMS, $phraseFirst->phrases);
        $this->assertSame([], $phraseFirst->terms);
    }

    /** An empty phrase is not stored, which is what the `!== ''` guard is for. */
    public function test_an_empty_phrase_is_not_stored(): void
    {
        $parsed = $this->parser->parse('alpha "" bravo');

        $this->assertSame(['alpha', 'bravo'], $parsed->terms);
        $this->assertSame([], $parsed->phrases, 'an empty phrase is nothing to search for');
    }

    /**
     * 🛑 A scope prefix is recognised whatever its case, and the slug is
     * lower-cased.
     *
     * §7.2's slugs are lower-case, so a reader typing `PROJECT:DocUp` means the
     * project `docup` — and a comparison against the snapshot's own slug would
     * fail for a reason the reader cannot see. The prefix and the operand are
     * two separate `strtolower` calls, so both are asserted.
     */
    public function test_a_scope_prefix_and_its_slug_are_case_insensitive(): void
    {
        $parsed = $this->parser->parse('PROJECT:DocUp/V2 term');

        $this->assertCount(1, $parsed->scopes);
        $this->assertSame('docup', $parsed->scopes[0]->slug);
        $this->assertSame('v2', $parsed->scopes[0]->version);
    }

    /** And the slug's own length cap, which nothing else exercises. */
    public function test_a_slug_is_capped_in_length(): void
    {
        $parsed = $this->parser->parse('project:'.str_repeat('a', 200).' term');

        $this->assertCount(1, $parsed->scopes);
        $this->assertSame(80, strlen($parsed->scopes[0]->slug));
    }

    /**
     * A token that is nothing but a colon-prefixed scope with no operand names
     * nothing, so it is not a scope request at all.
     */
    public function test_a_scope_prefix_with_no_operand_is_not_a_request(): void
    {
        $this->assertSame([], $this->parser->parse('project: term')->scopes);
        $this->assertSame([], $this->parser->parse('collection: term')->scopes);
    }

    /**
     * 🛑 `fromConfig(null)` and `fromConfig([])` both short-circuit.
     *
     * The guard is `$search === null || $search === []`, and with an `&&` a null
     * block would fall through to the reads below it. The result would be a
     * fatal on the one input that is guaranteed to occur — a build with no
     * `search:` block, which is most builds.
     */
    public function test_an_absent_search_block_short_circuits(): void
    {
        foreach ([null, []] as $absent) {
            $ranking = SearchRanking::fromConfig($absent);

            $this->assertSame(0, $ranking->rankFor('guide/index.html'));
            $this->assertTrue($ranking->ignores('404.html'), 'and the defaults apply');
        }
    }

    /**
     * 🛑 An `ignore:` key holding something that is not a list still counts as
     * declared.
     *
     * `ignore: internal/*` — a string rather than a list — is a plausible
     * mistake, and the question is what it means. It declares **nothing
     * usable**, so nothing is ignored; what it must not do is silently restore
     * Read the Docs' defaults, because the author would then see `404.html`
     * excluded and conclude their own pattern worked.
     *
     * This is the `||` in `is_array($ignoreBlock) || array_key_exists(…)`: with
     * an `&&` the key would not count as declared and the defaults would come
     * back.
     */
    public function test_an_unusable_ignore_key_is_still_a_declaration(): void
    {
        $ranking = SearchRanking::fromConfig(['ignore' => 'internal/*']);

        $this->assertFalse($ranking->ignores('404.html'), 'the defaults do not come back');
        $this->assertFalse($ranking->ignores('internal/secrets.html'), 'and the string declared nothing usable');
        $this->assertSame([], $ranking->describe()['ignore']);
    }

    /** A pattern that normalises to nothing is skipped, in both blocks. */
    public function test_a_pattern_that_normalises_to_nothing_is_skipped(): void
    {
        $ranking = SearchRanking::fromConfig([
            'ranking' => ['' => 5, '/' => 3, 'real/*' => 2],
            'ignore' => ['', './', 'drafts/*'],
        ]);

        $described = $ranking->describe();

        $this->assertSame(
            ['real/*'],
            array_column($described['ranking'], 'pattern'),
            'an empty pattern and a bare slash contribute nothing',
        );

        $this->assertSame(['drafts/*'], $described['ignore']);
    }

    /**
     * The pattern length cap.
     *
     * A 255-character bound on something that becomes a regex is the one place
     * in this class where the number is a safety property rather than a
     * tidiness one — {@see SearchRanking} translates a pattern by hand so there
     * is no backtracking to blow up, and the cap is the second layer.
     */
    public function test_a_pattern_is_capped_in_length(): void
    {
        $ranking = SearchRanking::fromConfig(['ignore' => [str_repeat('a', 400).'*']]);

        $pattern = $ranking->describe()['ignore'][0];

        $this->assertSame(255, strlen($pattern));
        $this->assertStringNotContainsString('*', $pattern, 'the cap cut the glob off the end');
    }

    /**
     * 🛑 A leading or trailing space in a pattern is trimmed.
     *
     * `ignore: [" 404.html"]` is a YAML author's whitespace, not a path, and a
     * pattern that kept it would match nothing — a silently ineffective
     * exclusion, which is the failure direction that matters here.
     */
    public function test_a_pattern_is_trimmed(): void
    {
        $this->assertTrue(
            SearchRanking::fromConfig(['ignore' => ['  404.html  ']])->ignores('404.html'),
        );
    }
}
