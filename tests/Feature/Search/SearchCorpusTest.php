<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Search;

use App\Access\ReaderContext;
use App\Search\Indexer;
use App\Search\LiteralTerm;
use App\Search\ParsedQuery;
use App\Search\QueryParser;
use App\Search\ScopeKind;
use App\Search\SearchQuery;
use App\Search\SearchScopes;
use App\Search\SearchState;
use App\Search\StructuredIndex;
use App\Support\Invalidation;
use App\Support\Uuid;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Storage;
use Tests\Support\CommitsSearchDocuments;
use Tests\TestCase;

/**
 * 🛑 §9.4's abuse corpus, `search` category.
 *
 * > §9.4: "Security-critical phases additionally … 🛑 **one named adversarial
 * > test appended to a permanent abuse corpus**." §9.4 names search among the
 * > security-critical phases, and §8.16 is three security requirements in one:
 * > server-side-only filtering (§8.16.6), a fail-closed generation gate
 * > (§8.12.21) and an injectable filter expression (§8.16.12).
 *
 * Twenty-three cases in three subjects, each driven here.
 *
 * ## 🛑 Not every case is a rejection
 *
 * Phase 25's lesson, recorded in `BrandingCorpusTest` and repeated by Phase 28:
 * one surviving control keeps every coarse case green, so each case names an
 * **exact** outcome. `search-022` is `falls_back` on purpose — an oversized
 * structured index is declined and §8.16.3's HTML extraction indexes the build
 * instead, so the build stays fully searchable by the other route. A corpus
 * that only ever expected refusals could not express that, and the distinction
 * is the interesting part.
 *
 * ## 🛑 The one that is not a defence but a direction
 *
 * `search-004` is the case worth reading twice. Every other query case is about
 * a reader **widening** their access; that one is about **narrowing** it. MySQL
 * boolean mode's `-` excludes documents, so a reader who could pass one could
 * subtract from a result set §8.16.6's filter had just defined — and because
 * MySQL has no escape for its boolean operators, the only safe handling is
 * removal.
 */
final class SearchCorpusTest extends TestCase
{
    use CommitsSearchDocuments;

    /** The outcomes a `search` case may name. Declared, so a typo fails. */
    private const array OUTCOMES = [
        // search_query
        'terms',
        'terms_separated',
        'no_exclusion',
        'scope_narrowed',
        'no_scope',
        'phrase',
        'bounded',
        'no_results',
        // search_scope
        'absent',
        'disabled',
        // search_index
        'not_indexed',
        'falls_back',
    ];

    private const array SUBJECTS = ['search_query', 'search_scope', 'search_index'];

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

    }

    protected function tearDown(): void
    {
        $this->cleanUpCommittedSearchData();

        parent::tearDown();
    }

    // ------------------------------------------------------------ the index

    public function test_the_category_exists_and_every_case_is_well_formed(): void
    {
        $cases = self::cases();

        $this->assertNotSame([], $cases, '§9.4 requires at least one named case for this phase');

        $ids = array_column($cases, 'id');

        $this->assertSame($ids, array_values(array_unique($ids)), 'no case id appears twice');

        foreach ($cases as $case) {
            $this->assertMatchesRegularExpression('/^search-\d{3}$/', $case['id']);
            $this->assertContains($case['subject'], self::SUBJECTS, $case['id'].' names a known subject');
            $this->assertContains($case['expect'], self::OUTCOMES, $case['id'].' names a declared outcome');
            $this->assertNotSame('', trim((string) $case['defends']), $case['id'].' must name what it defends');
            $this->assertNotSame('', trim((string) $case['note']), $case['id'].' must say why it matters');
        }
    }

    /**
     * 🛑 Every case is claimed by a driver below.
     *
     * The assertion Phase 28 added for the same reason: a case can otherwise be
     * appended to the corpus and never run, which looks like coverage and is
     * the opposite.
     */
    public function test_every_case_has_a_driver(): void
    {
        $driven = [
            ...array_column($this->queryCases(), 'id'),
            ...array_column($this->scopeCases(), 'id'),
            ...array_column($this->indexCases(), 'id'),
        ];

        sort($driven);
        $all = array_column(self::cases(), 'id');
        sort($all);

        $this->assertSame($all, $driven, 'every search case must be driven by a test in this file');
    }

    // --------------------------------------------------- subject: the query

    /**
     * 🛑 §8.16.12: not one of these produces a filter, a scope the reader may
     * not have, or an exclusion.
     *
     * Driven against {@see QueryParser} and then against both reductions,
     * because the parser's output is only half the defence — what the drivers
     * do with a term is the other half, and `search-004` is entirely about that.
     */
    public function test_no_hostile_query_becomes_a_filter_or_an_exclusion(): void
    {
        $parser = new QueryParser;

        foreach ($this->queryCases() as $case) {
            $id = $case['id'];

            $query = match ($id) {
                'search-009' => str_repeat('x', 10_000),
                'search-010' => implode(' ', array_fill(0, 1_000, 'term'.random_int(1, 9))),
                'search-008' => "accepted\x00admin",
                default => (string) $case['input'],
            };

            $parsed = $parser->parse($query);

            /*
             * 🛑 The invariant that holds for EVERY case, whatever its named
             * outcome: a scope request names a project, a collection or the
             * reader's own set, and its slug is already narrowed. There is no
             * value here a driver could read as syntax.
             */
            foreach ($parsed->scopes as $scope) {
                $this->assertContains($scope->kind, ScopeKind::cases());
                $this->assertMatchesRegularExpression('/^[a-z0-9._-]*$/', $scope->slug, $id);
                $this->assertLessThanOrEqual(80, strlen($scope->slug), $id);
            }

            match ($case['expect']) {
                'terms' => $this->assertSame([], $parsed->scopes, $id.' produces no scope request'),

                'terms_separated' => $this->assertSame(
                    ['accepted', 'admin'],
                    $parsed->terms,
                    $id.': a NUL separates rather than joins',
                ),

                'no_exclusion' => $this->assertNoTermCanExclude($parsed, $id),

                'scope_narrowed' => $this->assertSlugCannotTraverse($parsed, $id),

                'no_scope' => $this->assertSame([], $parsed->scopes, $id.' is not a scope request'),

                'phrase' => $this->assertSame(
                    ['scopes = restricted'],
                    $parsed->phrases,
                    $id.' is an exact-phrase search, not a filter',
                ),

                'bounded' => $this->assertBounded($parsed, $id),

                'no_results' => $this->assertSame(
                    [ScopeKind::Collection],
                    array_map(static fn (object $s): ScopeKind => $s->kind, $parsed->scopes),
                    $id.': `collection:` parses and reaches nothing',
                ),

                default => $this->fail($id.' has an outcome this driver does not handle'),
            };
        }
    }

    /**
     * 🛑 `search-005`, `search-006` and `search-012`: a scope request that
     * names nothing reaches nothing, through the real query path.
     *
     * The parser cases above prove the requests are built and narrowed; this
     * proves they are not honoured. For `collection:` that is deliberate —
     * §8.16.10's cross-project search is Phase 30's deliverable and honouring
     * it here would ship cross-project search with none of the
     * collection-membership checks that requirement describes. For the two
     * traversal attempts it is the narrowing arriving at its conclusion: the
     * slug names no project, so the authorised set is empty.
     */
    public function test_a_scope_request_that_names_nothing_reaches_nothing(): void
    {
        $fixture = $this->searchFixture('corpus');
        $version = $fixture->version('v1');

        $fixture->publish($version, ['html/index.html' => $this->page('corpusword')]);
        $fixture->channels(default: $version, stable: $version, latest: $version);

        app(Indexer::class)->indexProject($fixture->project);

        $mount = $fixture->mount('/');

        $this->assertNotSame([], app(SearchQuery::class)->forMount('corpusword', $mount)->results);

        foreach ([
            'search-012' => 'collection:platform corpusword',
            'search-005' => 'project:../../other-tenant corpusword',
            'search-006' => 'project:%2e%2e%2fother corpusword',
        ] as $id => $query) {
            $this->assertSame(
                [],
                app(SearchQuery::class)->forMount($query, $mount)->results,
                $id.': a scope naming nothing narrows the search to nothing',
            );
        }

        /*
         * 🛑 And the project's **own** slug still works, so the three above
         * failed for the right reason. Without this the test would pass against
         * a query path that refused every scoped query.
         */
        $this->assertNotSame(
            [],
            app(SearchQuery::class)->forMount(
                'project:'.$fixture->project->slug.' corpusword',
                $mount,
            )->results,
        );
    }

    // --------------------------------------------------- subject: the scope

    /**
     * 🛑 The four `search_scope` cases, each against the real query path.
     *
     * These are the cases a later phase will break. The gate, the generation
     * selection and the version filtering are three different mechanisms with
     * one symptom — an empty list — so each is asserted with the **state** as
     * well as the results: `absent` and `disabled` look identical to a reader
     * and must not look identical here.
     */
    public function test_the_scope_boundary_holds(): void
    {
        $fixture = $this->searchFixture('corpus-scope');

        $public = $fixture->version('v-open');
        $private = $fixture->version('v-shut', visibility: 'members');
        $hidden = $fixture->version('v-hidden', listed: false);

        $fixture->publish($public, ['html/index.html' => $this->page('openword')]);
        $fixture->publish($private, ['html/index.html' => $this->page('shutword')]);
        $fixture->publish($hidden, ['html/index.html' => $this->page('hiddenword')]);

        $fixture->channels(default: $public, stable: $private, latest: $hidden);

        app(Indexer::class)->indexProject($fixture->project);

        $mount = $fixture->mount('/');
        $query = app(SearchQuery::class);

        /* search-013: a members version is absent for an anonymous reader. */
        $this->assertSame([], $query->forMount('shutword', $mount)->results, 'search-013');
        $this->assertNotSame(
            [],
            $query->forMount('shutword', $mount, ReaderContext::member('corpus-reader'))->results,
            'search-013: and present for a member, so the filter is the reason',
        );

        /* search-016: §8.16.9 excludes a hidden version from the index entirely. */
        $this->assertSame([], $query->forMount('hiddenword', $mount)->results, 'search-016');
        $this->assertSame(
            [],
            $query->forMount('hiddenword', $mount, ReaderContext::member('corpus-reader'))->results,
            'search-016: not even for a member — it was never indexed (§8.16.9)',
        );

        /* search-014: a scope row at a generation nothing points at. */
        $live = (int) DB::table('projects')->where('id', $fixture->project->id)->value('search_generation');

        DB::table('search_mount_scopes')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $fixture->organisation->id,
            'project_id' => $fixture->project->id,
            'project_version_id' => $private->id,
            'component_mount_id' => null,
            'build_id' => Uuid::toBytes($fixture->buildIdOf($private)),
            'build_generation' => 1,
            'generation' => $live + 50,
            'scope' => 'public',
            'min_access' => 'public',
            'language' => 'en',
            'channel' => 'default',
            'created_at' => now(),
        ]);

        $keys = array_column(app(SearchScopes::class)->forMount($mount)->documentKeys(), 0);

        $this->assertNotContains(
            $fixture->buildIdOf($private),
            $keys,
            'search-014: a row at a generation the project is not pointing at is unreachable, '
            .'even one claiming `public` scope',
        );

        /* search-015: §8.12.21's gate — disabled, and distinguishable from absent. */
        $before = $query->forMount('openword', $mount);

        $this->assertSame(SearchState::Answered, $before->state);

        Invalidation::bumpAuthz(
            projectId: $fixture->project->id,
            cause: 'policy',
            policyWrite: true,
            organisationId: $fixture->organisation->id,
        );

        $after = $query->forMount('openword', $fixture->mount('/'));

        $this->assertSame([], $after->results, 'search-015');
        $this->assertSame(
            SearchState::GenerationStale,
            $after->state,
            'search-015: 🛑 disabled, not merely empty — the operator must be able to tell',
        );
    }

    // --------------------------------------------------- subject: the index

    /**
     * 🛑 The seven `search_index` cases: a hostile structured index inside a
     * build artifact.
     *
     * §14's threat model makes built documentation attacker-controlled, and a
     * `search_index.json` is a file in it — a project can commit one by hand.
     * The attack is a search result whose **URL** points somewhere else while
     * carrying this project's title, which a reader has every reason to trust.
     */
    public function test_a_hostile_structured_index_cannot_mint_a_url(): void
    {
        $fixture = $this->searchFixture('corpus-index');
        $version = $fixture->version('v1');

        $docs = [
            ['location' => '', 'title' => 'Home', 'text' => 'Landing page.'],
            ['location' => 'real/', 'title' => 'Real', 'text' => 'A genuine page about realword.'],
            // search-017
            ['location' => '../../../admin/', 'title' => 'Admin', 'text' => 'Mentions traversalword.'],
            // search-018
            ['location' => 'https://evil.example/x', 'title' => 'Off site', 'text' => 'Mentions absoluteword.'],
            // search-019
            ['location' => '/etc/passwd', 'title' => 'Root', 'text' => 'Mentions rootword.'],
            // search-020
            ['location' => 'never-published/', 'title' => 'Ghost', 'text' => 'Mentions ghostword.'],
        ];

        $fixture->publish($version, [
            'html/index.html' => $this->page('landingword'),
            'html/real/index.html' => $this->page('realword'),
            'html/search/search_index.json' => (string) json_encode(['config' => [], 'docs' => $docs]),
        ]);

        $fixture->channels(default: $version, stable: $version, latest: $version);

        app(Indexer::class)->indexProject($fixture->project);

        $mount = $fixture->mount('/');
        $query = app(SearchQuery::class);

        $this->assertNotSame([], $query->forMount('realword', $mount)->results, 'the genuine page is indexed');

        foreach ([
            'search-017' => 'traversalword',
            'search-018' => 'absoluteword',
            'search-019' => 'rootword',
            'search-020' => 'ghostword',
        ] as $id => $term) {
            $this->assertSame([], $query->forMount($term, $mount)->results, $id);
        }

        /*
         * 🛑 And nothing in the index points outside the project. Asserted over
         * every stored path rather than only over the four cases, because the
         * four are examples of a class and a fifth shape would pass the loop
         * above while failing this.
         */
        foreach (DB::table('search_documents')->pluck('path') as $path) {
            $this->assertIsString($path);
            $this->assertStringNotContainsString('..', $path);
            $this->assertStringNotContainsString('://', $path);
            $this->assertStringStartsNotWith('/', $path);
        }
    }

    /** 🛑 `search-021`: the Sphinx route's version of the same vector. */
    public function test_a_hostile_sphinx_page_name_is_not_indexed(): void
    {
        $fixture = $this->searchFixture('corpus-sphinx');
        $version = $fixture->version('v1');

        $fixture->publish($version, [
            'html/index.html' => $this->page('landingword'),
            'html/page/index.html' => $this->page('sphinxrealword'),
            'html/_json/globalcontext.json' => '{"project":"Fixture"}',
            'html/_json/page/index.fjson' => (string) json_encode([
                'current_page_name' => 'page/index',
                'title' => 'Real',
                'body' => '<section id="s"><h2>Real</h2><p>About sphinxrealword.</p></section>',
            ]),
            'html/_json/evil.fjson' => (string) json_encode([
                'current_page_name' => '../../secrets',
                'title' => 'Secrets',
                'body' => '<section id="s"><h2>Secrets</h2><p>About sphinxtraversalword.</p></section>',
            ]),
        ]);

        $fixture->channels(default: $version, stable: $version, latest: $version);

        app(Indexer::class)->indexProject($fixture->project);

        $mount = $fixture->mount('/');
        $query = app(SearchQuery::class);

        $this->assertNotSame([], $query->forMount('sphinxrealword', $mount)->results);
        $this->assertSame([], $query->forMount('sphinxtraversalword', $mount)->results, 'search-021');
    }

    /**
     * 🛑 `search-022`: an oversized structured index **falls back** rather than
     * failing.
     *
     * §9.2 budgets the indexer's peak memory and `json_decode` has no streaming
     * mode, so the whole file would become PHP arrays at once. The build is
     * still fully searchable — by §8.16.3's HTML route, which reads one capped
     * document at a time and is bounded whatever the site's size.
     *
     * So the large sites that most need the budget take the bounded route,
     * which is the right way round.
     */
    public function test_an_oversized_structured_index_falls_back_to_html_extraction(): void
    {
        $fixture = $this->searchFixture('corpus-big');
        $version = $fixture->version('v1');

        /*
         * Padded past the cap with a field the reader ignores, so the file is
         * oversized while still being a valid index — the point is the size,
         * not malformedness, and a malformed one is a different case.
         */
        $docs = [[
            'location' => 'real/',
            'title' => 'Real',
            'text' => 'Mentions structuredonlyword.',
            /*
             * 🛑 **Incompressible** padding. A megabyte of one repeated
             * character compresses to nothing, and §8.4's ingestor refuses an
             * archive whose compression ratio exceeds `max_compression_ratio`
             * — correctly, because that is a zip bomb's signature. So the
             * padding is random bytes: the file really is over the cap in the
             * store, which is what `StructuredIndex` reads from the manifest.
             */
            'padding' => base64_encode(random_bytes((int) (StructuredIndex::MAX_INDEX_BYTES * 0.8))),
        ]];

        $fixture->publish($version, [
            'html/index.html' => $this->page('landingword'),
            'html/real/index.html' => $this->page('htmlrouteword'),
            'html/search/search_index.json' => (string) json_encode(['config' => [], 'docs' => $docs]),
        ]);

        $fixture->channels(default: $version, stable: $version, latest: $version);

        app(Indexer::class)->indexProject($fixture->project);

        $this->assertSame(
            'html',
            DB::table('search_build_index')->where('state', 'live')->value('extracted_from'),
            'search-022: the oversized index was declined and HTML extraction took over',
        );

        $mount = $fixture->mount('/');
        $query = app(SearchQuery::class);

        $this->assertNotSame(
            [],
            $query->forMount('htmlrouteword', $mount)->results,
            'search-022: and the build is fully searchable by the other route',
        );

        $this->assertSame(
            [],
            $query->forMount('structuredonlyword', $mount)->results,
            "search-022: the index's own text is not in the corpus, which is what falling back means",
        );
    }

    /**
     * 🛑 `search-023`: a page that is nothing but navigation is not indexed.
     *
     * §8.16.3's stripping as an abuse case rather than a correctness one. A
     * page crafted so every term on the site appears in its navigation would
     * match every query and outrank the page the reader wanted — and Material's
     * own `search.html` is exactly this shape, which is why Read the Docs ships
     * it in the default ignore list.
     */
    public function test_a_page_that_is_only_navigation_is_not_indexed(): void
    {
        $fixture = $this->searchFixture('corpus-nav');
        $version = $fixture->version('v1');

        $fixture->publish($version, [
            'html/index.html' => $this->page('navrealword'),
            'html/sitemap/index.html' => '<!DOCTYPE html><html><head><meta charset="utf-8">'
                .'<title>Everything</title></head><body><main>'
                .'<nav><a href="/a">navbaitword</a><a href="/b">navbaitword</a></nav>'
                .'<div class="md-sidebar"><p>navbaitword navbaitword</p></div>'
                .'</main></body></html>',
        ]);

        $fixture->channels(default: $version, stable: $version, latest: $version);

        app(Indexer::class)->indexProject($fixture->project);

        $mount = $fixture->mount('/');

        $this->assertNotSame([], app(SearchQuery::class)->forMount('navrealword', $mount)->results);
        $this->assertSame(
            [],
            app(SearchQuery::class)->forMount('navbaitword', $mount)->results,
            'search-023: navigation text is not content, however much of it there is',
        );
    }

    // --------------------------------------------------------------- helpers

    /**
     * 🛑 A narrowed slug cannot act as a path.
     *
     * `project:../../other-tenant` does **not** produce an empty slug — the
     * dots and the hyphen are legal in a slug (`my.project` is a real one), so
     * what survives is `....other-tenant`. That is the right outcome and the
     * assertion has to say why it is safe rather than asserting absence:
     * nothing separates the segments, so there are no segments, so there is
     * nothing to traverse. The slug then names no project and
     * {@see SearchScopes} narrows the search to nothing —
     * asserted through the real query path by
     * {@see self::test_a_scope_request_that_names_nothing_reaches_nothing()}.
     */
    private function assertSlugCannotTraverse(ParsedQuery $parsed, string $id): void
    {
        $this->assertNotSame([], $parsed->scopes, $id.': the prefix is still recognised as a scope request');

        foreach ($parsed->scopes as $scope) {
            foreach (['/', chr(92), '%', ':', '?', '#', ' '] as $separator) {
                $this->assertStringNotContainsString(
                    $separator,
                    $scope->slug,
                    $id.': a slug with no separator has no segments to traverse',
                );
            }

            $this->assertNotSame('', $scope->slug, $id.': and it is not empty, which would be a different case');
        }
    }

    /**
     * 🛑 No reduced term can carry an exclusion into either engine.
     *
     * Checked against the **union** both drivers strip, which is the set
     * {@see LiteralTerm} owns — so this case cannot pass on one
     * engine and fail on the other, which is the divergence that class exists
     * to prevent.
     */
    private function assertNoTermCanExclude(ParsedQuery $parsed, string $id): void
    {
        $this->assertSame(
            ['authentication', '-internal'],
            $parsed->terms,
            $id.': the parser keeps the term exactly as typed — the reduction happens at the engine boundary',
        );

        foreach ($parsed->terms as $term) {
            foreach (LiteralTerm::wordsOf($term) as $word) {
                foreach (['-', '+', '~', '*', '"', '(', ')', '<', '>', '@', '^'] as $operator) {
                    $this->assertStringNotContainsString(
                        $operator,
                        $word,
                        $id.': a reduced term must carry no operator of either engine',
                    );
                }
            }
        }
    }

    private function assertBounded(ParsedQuery $parsed, string $id): void
    {
        $this->assertLessThanOrEqual(QueryParser::MAX_TERMS, count($parsed->terms) + count($parsed->phrases), $id);

        foreach ($parsed->terms as $term) {
            $this->assertLessThanOrEqual(QueryParser::MAX_TERM_LENGTH, mb_strlen($term), $id);
        }
    }

    private function page(string $term): string
    {
        return '<!DOCTYPE html><html><head><meta charset="utf-8"><title>T</title></head>'
            .'<body><main><h1 id="t">Title</h1><h2 id="s">Section</h2>'
            .'<p>Body mentioning '.$term.' once.</p></main></body></html>';
    }

    /** @return list<array<string, mixed>> */
    private function queryCases(): array
    {
        return $this->casesFor('search_query');
    }

    /** @return list<array<string, mixed>> */
    private function scopeCases(): array
    {
        return $this->casesFor('search_scope');
    }

    /** @return list<array<string, mixed>> */
    private function indexCases(): array
    {
        return $this->casesFor('search_index');
    }

    /** @return list<array<string, mixed>> */
    private function casesFor(string $subject): array
    {
        return array_values(array_filter(
            self::cases(),
            static fn (array $case): bool => $case['subject'] === $subject,
        ));
    }

    /** @return list<array<string, mixed>> */
    private static function cases(): array
    {
        /** @var array{cases: list<array<string, mixed>>} $corpus */
        $corpus = json_decode(
            File::get(base_path('tests/Fixtures/AbuseCorpus/corpus.json')),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        return array_values(array_filter(
            $corpus['cases'],
            static fn (array $case): bool => ($case['category'] ?? null) === 'search',
        ));
    }
}
