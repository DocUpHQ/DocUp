<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Search;

use App\Search\ParsedQuery;
use App\Search\QueryParser;
use App\Search\ScopeKind;
use PHPUnit\Framework\TestCase;

/**
 * 🛑 §8.16.12's minimum syntax, and the three things it refuses.
 *
 * > "implicit AND between terms, exact phrase in double quotes, and the scope
 * > filters `project:<slug>[/<version>]`, `collection:<slug>` and `self:me` …
 * > Syntax a driver cannot support … MUST degrade to a literal term rather
 * > than erroring. 🛑 Filter expressions MUST NOT be accepted from the client in
 * > any form."
 *
 * The degradation rule has as many tests as the syntax does, because it is the
 * half that makes "the identical suite passes on both engines" true: a parser
 * that understood `OR` on one engine and ignored it on the other would make the
 * claim false while every test still passed.
 */
final class QueryParserTest extends TestCase
{
    private QueryParser $parser;

    protected function setUp(): void
    {
        parent::setUp();

        $this->parser = new QueryParser;
    }

    public function test_bare_words_are_terms_and_are_implicitly_anded(): void
    {
        $query = $this->parser->parse('access token rotation');

        $this->assertSame(['access', 'token', 'rotation'], $query->terms);
        $this->assertSame([], $query->phrases);
        $this->assertSame([], $query->scopes);
    }

    public function test_double_quotes_make_an_exact_phrase(): void
    {
        $query = $this->parser->parse('rotate "access token" now');

        $this->assertSame(['rotate', 'now'], $query->terms);
        $this->assertSame(['access token'], $query->phrases);
    }

    /**
     * 🛑 An unterminated quote is the normal state of a search box.
     *
     * §8.15.8's combobox sends a request per keystroke, so every phrase is
     * unterminated while it is being typed. An error here would make the
     * control flash a validation message on every second character.
     */
    public function test_an_unterminated_quote_is_a_phrase_and_not_an_error(): void
    {
        $query = $this->parser->parse('rotate "access tok');

        $this->assertSame(['rotate'], $query->terms);
        $this->assertSame(['access tok'], $query->phrases);
    }

    public function test_the_three_scope_filters_parse(): void
    {
        $query = $this->parser->parse('project:docup/v2 collection:platform self:me tokens');

        $this->assertSame(['tokens'], $query->terms, 'a scope prefix is consumed, not also a term');
        $this->assertCount(3, $query->scopes);

        $this->assertSame(ScopeKind::Project, $query->scopes[0]->kind);
        $this->assertSame('docup', $query->scopes[0]->slug);
        $this->assertSame('v2', $query->scopes[0]->version);

        $this->assertSame(ScopeKind::Collection, $query->scopes[1]->kind);
        $this->assertSame('platform', $query->scopes[1]->slug);

        $this->assertSame(ScopeKind::Accessible, $query->scopes[2]->kind);
    }

    /**
     * 🛑 A scope prefix must not ALSO become a term.
     *
     * Leaving it in makes `project:docup auth` search for the literal text
     * `project:docup`, which matches nothing — so every scoped query would
     * return nothing and the scope would look like it had filtered everything
     * out.
     */
    public function test_a_scope_prefix_is_not_also_searched_for(): void
    {
        $query = $this->parser->parse('project:docup authentication');

        $this->assertSame(['authentication'], $query->terms);
        $this->assertNotContains('project:docup', $query->terms);
    }

    /**
     * 🛑 `self:` with anything but `me` is a typo, not a filter.
     *
     * A typo that silently became "the reader's whole accessible set" would
     * widen the search the reader asked to narrow.
     */
    public function test_self_only_accepts_me(): void
    {
        $this->assertSame([], $this->parser->parse('self:everything')->scopes);
        $this->assertCount(1, $this->parser->parse('self:ME')->scopes, 'the operand is case-insensitive');
    }

    /**
     * Documentation is full of colon-bearing words. Treating every one as a
     * filter would make them unsearchable.
     */
    public function test_an_unknown_prefix_is_an_ordinary_term(): void
    {
        $query = $this->parser->parse('note:important http: TODO:later');

        $this->assertSame(['note:important', 'http:', 'TODO:later'], $query->terms);
        $this->assertSame([], $query->scopes);
    }

    /**
     * 🛑 §8.16.12's degradation rule: no operators exist, so none errors.
     *
     * `AND`, `OR`, `NOT`, `~`, `*`, `+`, `-`, `^` and `(` are **characters in a
     * term**. A reader searching for `C++` gets a search for `C++`.
     */
    public function test_operators_are_ordinary_characters(): void
    {
        $query = $this->parser->parse('foo OR bar NOT baz ~fuzzy prefix* +must -not C++');

        $this->assertSame(
            ['foo', 'OR', 'bar', 'NOT', 'baz', '~fuzzy', 'prefix*', '+must', '-not', 'C++'],
            $query->terms,
        );
    }

    /**
     * 🛑 The abuse corpus's subject, as a unit test: a filter expression is a
     * term.
     *
     * Nothing this parser returns is an engine filter, and
     * {@see ParsedQuery} has no field that could hold one — which
     * is §8.16.12's "Filter expressions MUST NOT be accepted from the client in
     * any form" expressed as a type rather than as a check.
     */
    public function test_a_meilisearch_filter_expression_is_just_terms(): void
    {
        $query = $this->parser->parse('scopes = "restricted" OR build_id EXISTS');

        $this->assertSame([], $query->scopes, 'no scope request was produced');
        $this->assertNotEmpty($query->terms);

        foreach ($query->terms as $term) {
            $this->assertStringNotContainsString('"', $term, 'a quote never survives into a term');
        }
    }

    /** Control characters become separators, not removed. */
    public function test_control_characters_separate_rather_than_join(): void
    {
        $query = $this->parser->parse("a\x00b\nc");

        $this->assertSame(['a', 'b', 'c'], $query->terms, 'a NUL must not silently join two terms');
    }

    public function test_terms_are_capped_in_number_and_in_length(): void
    {
        $many = $this->parser->parse(implode(' ', array_fill(0, 100, 'word')));

        $this->assertCount(QueryParser::MAX_TERMS, $many->terms);

        $long = $this->parser->parse(str_repeat('x', 500));

        $this->assertSame(QueryParser::MAX_TERM_LENGTH, mb_strlen($long->terms[0]));
    }

    public function test_an_empty_query_is_empty(): void
    {
        $this->assertTrue($this->parser->parse('')->isEmpty());
        $this->assertTrue($this->parser->parse('   ')->isEmpty());
        $this->assertTrue($this->parser->parse('project:docup')->isEmpty(), 'a scope alone matches nothing');
    }

    /**
     * 🛑 A slug is narrowed to §7.2's character set before it leaves the parser.
     *
     * Defence in depth: the drivers escape too, and this is the layer that
     * holds if one of them stops. A comma, a quote or a bracket can never reach
     * a filter expression even through a bug downstream.
     */
    public function test_a_slug_is_narrowed_to_safe_characters(): void
    {
        $query = $this->parser->parse('project:docup,evil) term');

        $this->assertSame('docupevil', $query->scopes[0]->slug);
        $this->assertSame(['term'], $query->terms);
    }

    /**
     * And a quote inside a scope token **ends** it, because the phrase splitter
     * runs first.
     *
     * Worth asserting rather than assuming: it means a `"` can never be inside
     * a slug by any route, not merely that it is stripped from one. The
     * narrowing above is the second layer; this is the first.
     */
    public function test_a_quote_ends_a_scope_token_before_narrowing_sees_it(): void
    {
        $query = $this->parser->parse('project:do"cup" term');

        $this->assertSame('do', $query->scopes[0]->slug);
        $this->assertSame(['cup'], $query->phrases);
    }

    /** The raw string is kept for §8.16.10's round-trip, and read by nothing else. */
    public function test_the_raw_query_round_trips(): void
    {
        $raw = 'rotate "access token" project:docup';

        $this->assertSame($raw, $this->parser->parse($raw)->raw);
    }
}
