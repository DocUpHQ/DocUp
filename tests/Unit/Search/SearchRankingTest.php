<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Search;

use App\Search\SearchRanking;
use PHPUnit\Framework\TestCase;

/**
 * §8.16.3's `search.ranking` and `search.ignore`, and §8.4.2's compatibility
 * promise about them.
 *
 * > §8.4.2: "The schema MUST be a **key- and value-compatible superset of
 * > `.readthedocs.yaml` v2** … The preserved keys are: … and
 * > `search.{ranking,ignore}`. 'Keep your existing config file' must be true in
 * > practice, not approximately."
 *
 * So the three behaviours copied from Read the Docs each have a test: the last
 * matching pattern wins, `*` crosses `/`, and the default ignore list is not
 * empty. Each one is a case where a "better" rule would silently change a
 * migrated project's search results.
 */
final class SearchRankingTest extends TestCase
{
    public function test_nothing_declared_means_rank_zero(): void
    {
        $ranking = SearchRanking::none();

        $this->assertSame(0, $ranking->rankFor('guide/index.html'));
    }

    /**
     * 🛑 The **last** matching pattern wins, which is Read the Docs' rule.
     *
     * A project writing `api/*: -1` then `api/v2/*: 4` expects `api/v2/` to
     * rank +4. "Most specific wins" gives the same answer here and a different
     * one for a pair where neither pattern contains the other — so copying the
     * rule keeps a migrated config identical rather than nearly identical.
     */
    public function test_the_last_matching_pattern_wins(): void
    {
        $ranking = SearchRanking::fromConfig([
            'ranking' => [
                'api/*' => -1,
                'api/v2/*' => 4,
            ],
        ]);

        $this->assertSame(4, $ranking->rankFor('api/v2/index.html'));
        $this->assertSame(-1, $ranking->rankFor('api/v1/index.html'));
        $this->assertSame(0, $ranking->rankFor('guide/index.html'));
    }

    /** And the reverse order gives the reverse answer, which is the point. */
    public function test_declaration_order_is_load_bearing(): void
    {
        $ranking = SearchRanking::fromConfig([
            'ranking' => [
                'api/v2/*' => 4,
                'api/*' => -1,
            ],
        ]);

        $this->assertSame(-1, $ranking->rankFor('api/v2/index.html'));
    }

    /**
     * 🛑 `*` crosses `/`, because Read the Docs matches with Python's `fnmatch`
     * and that is what it does there.
     */
    public function test_a_star_crosses_path_separators(): void
    {
        $ranking = SearchRanking::fromConfig(['ranking' => ['api/*' => 5]]);

        $this->assertSame(5, $ranking->rankFor('api/v2/reference/index.html'));
    }

    public function test_a_question_mark_matches_one_character(): void
    {
        $ranking = SearchRanking::fromConfig(['ranking' => ['v?.html' => 3]]);

        $this->assertSame(3, $ranking->rankFor('v1.html'));
        $this->assertSame(0, $ranking->rankFor('v10.html'));
    }

    /** §8.16.3's bounds, applied to a value outside them. */
    public function test_a_rank_is_clamped_to_the_stated_bounds(): void
    {
        $ranking = SearchRanking::fromConfig([
            'ranking' => ['high/*' => 500, 'low/*' => -500],
        ]);

        $this->assertSame(SearchRanking::MAX_RANK, $ranking->rankFor('high/index.html'));
        $this->assertSame(SearchRanking::MIN_RANK, $ranking->rankFor('low/index.html'));
    }

    /**
     * 🛑 Hostile input: the block came from a repository's own YAML.
     *
     * A rank of `true`, of `"-1"` or of an array is not a rank. §8.4's parser
     * has already refused a malformed document; what reaches here is a
     * well-formed document saying something unreasonable.
     */
    public function test_a_non_integer_rank_is_ignored(): void
    {
        $ranking = SearchRanking::fromConfig([
            'ranking' => [
                'a/*' => true,
                'b/*' => '4',
                'c/*' => ['nested'],
                'd/*' => 2,
            ],
        ]);

        $this->assertSame(0, $ranking->rankFor('a/index.html'));
        $this->assertSame(0, $ranking->rankFor('b/index.html'));
        $this->assertSame(0, $ranking->rankFor('c/index.html'));
        $this->assertSame(2, $ranking->rankFor('d/index.html'), 'and a real one still works');
    }

    /**
     * 🛑 Read the Docs' default ignore list, which is not empty.
     *
     * Material's `search.html` contains every term on the site in its template,
     * so it matches every query and outranks the page the reader wanted. A
     * migrating project that never wrote an `ignore:` key still expects its 404
     * page not to be a search result.
     */
    public function test_the_default_ignore_list_is_read_the_docs_own(): void
    {
        $ranking = SearchRanking::none();

        foreach (SearchRanking::DEFAULT_IGNORE as $path) {
            $this->assertTrue($ranking->ignores($path), $path.' is ignored by default');
        }

        $this->assertFalse($ranking->ignores('guide/index.html'));
    }

    /**
     * 🛑 A declared `ignore:` **replaces** the defaults, which is also Read the
     * Docs' behaviour.
     *
     * So `ignore: [internal/*]` makes `404.html` searchable again. That is on
     * the author rather than a surprise DocUp invents — and a product that
     * silently merged the two would differ from the upstream the config was
     * written against.
     */
    public function test_a_declared_ignore_list_replaces_the_defaults(): void
    {
        $ranking = SearchRanking::fromConfig(['ignore' => ['internal/*']]);

        $this->assertTrue($ranking->ignores('internal/secrets.html'));
        $this->assertFalse($ranking->ignores('404.html'), 'the author replaced the list');
    }

    /** An explicitly empty list is an author saying "index everything". */
    public function test_an_empty_ignore_list_is_honoured(): void
    {
        $ranking = SearchRanking::fromConfig(['ignore' => []]);

        $this->assertFalse($ranking->ignores('404.html'));
        $this->assertFalse($ranking->ignores('search.html'));
    }

    /** A leading slash is the one thing an author writing a path gets wrong. */
    public function test_a_leading_slash_or_dot_slash_still_matches(): void
    {
        $ranking = SearchRanking::fromConfig(['ignore' => ['/private.html', './drafts/*']]);

        $this->assertTrue($ranking->ignores('private.html'));
        $this->assertTrue($ranking->ignores('drafts/one.html'));
    }

    /** The declared set is reportable, for the operator UI and `doctor`. */
    public function test_the_declared_patterns_are_reportable(): void
    {
        $described = SearchRanking::fromConfig([
            'ranking' => ['api/*' => 3],
            'ignore' => ['internal/*'],
        ])->describe();

        $this->assertSame([['pattern' => 'api/*', 'rank' => 3]], $described['ranking']);
        $this->assertSame(['internal/*'], $described['ignore']);
    }

    /**
     * A pattern is a glob and never a regex: the translation understands `*`
     * and `?` and treats everything else as a literal, so there is no
     * backtracking to blow up and no libc difference between installations.
     */
    public function test_a_regex_metacharacter_is_a_literal(): void
    {
        $ranking = SearchRanking::fromConfig(['ignore' => ['a.b.html']]);

        $this->assertTrue($ranking->ignores('a.b.html'));
        $this->assertFalse($ranking->ignores('axbxhtml'), 'the dot is a dot');
    }
}
