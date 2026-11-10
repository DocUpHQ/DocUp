<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Search;

use App\Search\BuildIndexReport;
use App\Search\SearchRanking;
use App\Search\Section;
use App\Search\SectionExtractor;
use PHPUnit\Framework\TestCase;

/**
 * §8.16.3's extraction, rule by rule.
 *
 * > "One search document per HTML **section** (heading anchor), extracted with
 * > main-content detection (`role="main"` → `<main>` → parent of the first
 * > `<h1>` → `<body>`), navigation/script/anchor-link stripping, nested title
 * > and content boosts, and a −10…+10 per-page rank."
 *
 * Every clause of that sentence has a test here, and the detection **order**
 * has four — because the order is the part that is easy to get subtly wrong and
 * impossible to notice: a theme that marks both `role="main"` and `<main>` will
 * work either way, and the one that only marks the outer wrapper will index its
 * own sidebar for ever.
 */
final class SectionExtractorTest extends TestCase
{
    private SectionExtractor $extractor;

    protected function setUp(): void
    {
        parent::setUp();

        $this->extractor = new SectionExtractor;
    }

    public function test_one_document_per_heading_anchor(): void
    {
        $sections = $this->extract(
            '<main>'
            .'<h1 id="top">Guide</h1><p>Intro prose.</p>'
            .'<h2 id="install">Install</h2><p>Run the installer.</p>'
            .'<h2 id="upgrade">Upgrade</h2><p>Back up first.</p>'
            .'</main>'
        );

        $this->assertSame(['top', 'install', 'upgrade'], array_map(
            static fn (Section $s): ?string => $s->anchor,
            $sections,
        ));

        $this->assertSame('Run the installer.', $sections[1]->content);
        $this->assertSame('Install', $sections[1]->title);
        $this->assertSame('Guide', $sections[1]->pageTitle, 'every section carries the page title');
    }

    /**
     * 🛑 §8.16.3's detection order: `role="main"` wins over `<main>`.
     *
     * Sphinx's and Read the Docs' themes set `role="main"` deliberately on the
     * content, while a layout wrapper may also be a `<main>`. Getting this the
     * wrong way round indexes the sidebar on every Sphinx site in existence.
     */
    public function test_role_main_wins_over_the_main_element(): void
    {
        $sections = $this->extract(
            '<main><p>Layout wrapper text.</p>'
            .'<div role="main"><h1 id="t">Title</h1><p>Real content.</p></div>'
            .'</main>'
        );

        $this->assertCount(1, $sections);
        $this->assertSame('Real content.', $sections[0]->content);
    }

    public function test_the_main_element_wins_over_the_h1s_parent(): void
    {
        $sections = $this->extract(
            '<div><p>Outside.</p><main><h1 id="t">Title</h1><p>Inside.</p></main></div>'
        );

        $this->assertCount(1, $sections);
        $this->assertSame('Inside.', $sections[0]->content);
    }

    /**
     * The third rung: a theme that marks nothing. mdBook and some Docusaurus
     * versions are this case, and it works because a generated page's `h1` is
     * in the content while a sidebar's titles are not `h1`s.
     */
    public function test_the_h1s_parent_is_the_third_rung(): void
    {
        $sections = $this->extract(
            '<div class="page"><h1 id="t">Title</h1><p>Body.</p></div>'
            .'<div class="other"><p>Elsewhere.</p></div>'
        );

        $this->assertCount(1, $sections);
        $this->assertSame('Body.', $sections[0]->content);
        $this->assertStringNotContainsString('Elsewhere', $sections[0]->content);
    }

    /** The last rung. `<body>` indexes everything, which is why stripping exists. */
    public function test_body_is_the_last_rung(): void
    {
        $sections = $this->extract('<p>No landmark anywhere.</p>');

        $this->assertCount(1, $sections);
        $this->assertSame('No landmark anywhere.', $sections[0]->content);
    }

    /**
     * 🛑 The strip that decides whether search is usable at all.
     *
     * A Sphinx sidebar repeats the whole table of contents on **every** page.
     * Left in, every page matches every other page's title and the top result
     * for any term is whichever row the relevance sort happened to pick.
     */
    public function test_navigation_script_and_style_are_stripped(): void
    {
        $sections = $this->extract(
            '<main>'
            .'<nav><a href="/a">Alpha</a><a href="/b">Bravo</a></nav>'
            .'<div class="sphinxsidebar"><p>Table of contents</p></div>'
            .'<script>var secret = "scriptword";</script>'
            .'<style>.sidebar { color: stylekeyword; }</style>'
            .'<template><p>templateword</p></template>'
            .'<h1 id="t">Title</h1><p>Real prose.</p>'
            .'</main>'
        );

        $this->assertCount(1, $sections);

        foreach (['Alpha', 'Bravo', 'Table of contents', 'scriptword', 'stylekeyword', 'templateword'] as $gone) {
            $this->assertStringNotContainsString($gone, $sections[0]->content, $gone.' must not be indexed');
        }

        $this->assertSame('Real prose.', $sections[0]->content);
    }

    /**
     * 🛑 The permalink glyph, which ends up in the **title** if it survives —
     * and the stored title is what a result list shows a reader.
     */
    public function test_permalink_anchors_are_stripped_from_titles(): void
    {
        $sections = $this->extract(
            '<main><h2 id="install">Install<a class="headerlink" href="#install">¶</a></h2><p>Text.</p></main>'
        );

        $this->assertSame('Install', $sections[0]->title);
        $this->assertStringNotContainsString('¶', $sections[0]->title);
    }

    /** `aria-hidden` is a decorative glyph: not text, often not even typeable. */
    public function test_aria_hidden_subtrees_are_stripped(): void
    {
        $sections = $this->extract(
            '<main><h1 id="t">Title <span aria-hidden="true">'."\u{e801}".'</span></h1><p>Body.</p></main>'
        );

        $this->assertSame('Title', $sections[0]->title);
    }

    /**
     * §8.16.3's "nested title", which is the heading ancestry and not the path.
     */
    public function test_the_nested_title_is_the_heading_ancestry(): void
    {
        $sections = $this->extract(
            '<main>'
            .'<h1 id="g">Guide</h1>'
            .'<h2 id="auth">Authentication</h2>'
            .'<h3 id="tokens">Tokens</h3><p>About tokens.</p>'
            .'</main>'
        );

        $tokens = $sections[2];

        $this->assertSame('Tokens', $tokens->title);
        $this->assertSame('Guide'.Section::HEADING_SEPARATOR.'Authentication', $tokens->headingPath);
    }

    /**
     * 🛑 The ancestry is **trimmed** at each level, not accumulated.
     *
     * Without the trim the nested title grows monotonically and a page with
     * twenty headings ends with a 2 KB `heading_path` made of every heading
     * that came before it — wrong, and the reason the column has a length.
     */
    public function test_a_shallower_heading_replaces_rather_than_nests(): void
    {
        $sections = $this->extract(
            '<main>'
            .'<h1 id="g">Guide</h1>'
            .'<h2 id="a">Alpha</h2><h3 id="a1">Alpha one</h3><p>x</p>'
            .'<h2 id="b">Bravo</h2><p>y</p>'
            .'</main>'
        );

        $bravo = $sections[3];

        $this->assertSame('Bravo', $bravo->title);
        $this->assertSame('Guide', $bravo->headingPath, 'Alpha is not an ancestor of Bravo');
    }

    /**
     * 🛑 Sphinx's shape: the `id` is on the wrapping `<section>`, not on the
     * heading. Without the ancestor fallback every Sphinx section links to the
     * page top, which is the single most visible way a result can be wrong.
     */
    public function test_an_anchor_is_taken_from_the_nearest_ancestor_when_the_heading_has_none(): void
    {
        $sections = $this->extract(
            '<main><section id="installation"><h2>Installation</h2><p>Steps.</p></section></main>'
        );

        $this->assertSame('installation', $sections[0]->anchor);
    }

    /** And it stops, rather than walking up to the page wrapper. */
    public function test_the_ancestor_walk_is_bounded(): void
    {
        $sections = $this->extract(
            '<main id="content"><div><div><div><h2>Deep</h2><p>Text.</p></div></div></div></main>'
        );

        $this->assertNull(
            $sections[0]->anchor,
            'an unbounded walk would find #content, which is a link to the top wearing a fragment',
        );
    }

    /** Text before the first heading is the page-level section, with no anchor. */
    public function test_text_before_the_first_heading_becomes_a_page_level_section(): void
    {
        $sections = $this->extract(
            '<main><p>Lead paragraph.</p><h2 id="s">Section</h2><p>Body.</p></main>'
        );

        $this->assertCount(2, $sections);
        $this->assertNull($sections[0]->anchor);
        $this->assertSame('Lead paragraph.', $sections[0]->content);
    }

    /**
     * 🛑 Block elements break text; inline elements do not.
     *
     * `<em>auth</em>entication` is one word to a reader and must be one word in
     * the index, or the term they type finds nothing. Two adjacent paragraphs
     * are two, or their last and first words merge into a term nobody will ever
     * search for.
     */
    public function test_inline_elements_do_not_break_words_and_blocks_do(): void
    {
        $sections = $this->extract(
            '<main><h1 id="t">T</h1><p><em>auth</em>entication</p><p>second</p></main>'
        );

        $this->assertSame('authentication second', $sections[0]->content);
    }

    /** §8.16.3's rank, clamped to the stated bounds. */
    public function test_the_page_rank_comes_from_search_ranking_and_is_clamped(): void
    {
        $ranking = SearchRanking::fromConfig(['ranking' => ['guide/*' => 99]]);

        $sections = $this->extractor->extract(
            'guide/index.html',
            '<html><body><main><h1 id="t">T</h1><p>Body.</p></main></body></html>',
            $ranking,
        );

        $this->assertSame(SearchRanking::MAX_RANK, $sections[0]->rank);
    }

    /** §8.16.3's `search.ignore`: the page is not indexed at all. */
    public function test_an_ignored_page_yields_nothing(): void
    {
        $ranking = SearchRanking::fromConfig(['ignore' => ['internal/*']]);

        $this->assertSame([], $this->extractor->extract(
            'internal/secrets.html',
            '<html><body><main><h1 id="t">T</h1><p>Body.</p></main></body></html>',
            $ranking,
        ));
    }

    /**
     * 🛑 §9.2's budget, as a refusal rather than a hope.
     *
     * A DOM is roughly an order of magnitude larger than its bytes, so one
     * pathological page would otherwise decide the whole indexer's peak. The
     * page loses search and {@see BuildIndexReport} counts it.
     */
    public function test_an_oversized_document_is_skipped(): void
    {
        $filler = str_repeat('<p>'.str_repeat('x', 1000).'</p>', 9000);

        $this->assertGreaterThan(SectionExtractor::MAX_DOCUMENT_BYTES, strlen($filler));
        $this->assertSame([], $this->extract($filler));
    }

    /** A document the HTML5 parser refuses is a page no browser renders. */
    public function test_an_empty_document_yields_nothing(): void
    {
        $this->assertSame([], $this->extractor->extract('empty.html', '', SearchRanking::none()));
    }

    /**
     * §8.16.4's fragment route: no main-content detection, because the fragment
     * **is** the content — but the stripping still runs.
     */
    public function test_a_fragment_is_sectioned_without_main_content_detection(): void
    {
        $sections = $this->extractor->fragment(
            'guide/index.html',
            '<section id="install"><h2>Install<a class="headerlink" href="#install">¶</a></h2>'
            .'<p>Steps.</p><script>var x = "hidden";</script></section>',
            SearchRanking::none(),
            'The Guide',
        );

        $this->assertCount(1, $sections);
        $this->assertSame('install', $sections[0]->anchor);
        $this->assertSame('Install', $sections[0]->title);
        $this->assertSame('Steps.', $sections[0]->content);
        $this->assertSame('The Guide', $sections[0]->pageTitle, "the generator's own title is used");
    }

    /**
     * The section body is capped, and the cap is applied while appending.
     *
     * Measuring the joined string per append is quadratic, and a `singlehtml`
     * build is exactly the input that finds that out.
     */
    public function test_a_section_body_is_capped(): void
    {
        $sections = $this->extract(
            '<main><h1 id="t">T</h1><p>'.str_repeat('word ', 20_000).'</p></main>'
        );

        $this->assertLessThanOrEqual(
            SectionExtractor::MAX_CONTENT_CHARS,
            mb_strlen($sections[0]->content),
        );
    }

    /** @return list<Section> */
    private function extract(string $body): array
    {
        return $this->extractor->extract(
            'page.html',
            '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Page — Project</title></head>'
            .'<body>'.$body.'</body></html>',
            SearchRanking::none(),
        );
    }
}
