<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Search;

use App\Access\ReaderContext;
use App\Auth\OrganisationContext;
use App\Search\DocumentHit;
use App\Search\EngineCapability;
use App\Search\Engines\MeilisearchEngine;
use App\Search\Indexer;
use App\Search\SearchDriver;
use App\Search\SearchEngine;
use App\Search\SearchOutcome;
use App\Search\SearchQuery;
use App\Search\SearchResult;
use App\Search\SearchState;
use App\Support\Uuid;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Tests\Support\CommitsSearchDocuments;
use Tests\Support\SearchFixture;
use Tests\TestCase;

/**
 * 🛑 §17's Phase 29 exit criterion 4: "Switching to Meilisearch passes the
 * identical suite."
 *
 * **This file is that suite.** It is driver-agnostic by construction — it
 * resolves {@see SearchEngine} from the container and never names a driver
 * except to report which one ran — so "the identical suite" is literal rather
 * than a claim about two files that look similar.
 *
 * - `./vendor/bin/pest tests/Feature/Search/EngineContractTest.php` runs it
 *   against the shipped default.
 * - `DOCUP_SEARCH_DRIVER=meilisearch` runs the same assertions against a real
 *   Meilisearch. CI does that in its own job, against a service container, with
 *   `DOCUP_SEARCH_E2E=1` so an unreachable engine **fails** instead of
 *   skipping — which is the whole reason that job exists.
 *
 * ## 🛑 What this suite asserts, and what it deliberately does not
 *
 * §8.16.12 defines a "minimum query syntax every `SearchEngine` driver
 * honours", and that is what is asserted: implicit AND, exact phrases, the
 * scope filters, the visibility filter, and §8.16.3's **ordering**.
 *
 * It does **not** assert relevance numbers, typo behaviour or stemming. Those
 * differ between the engines by design — Meilisearch tolerates typos and the
 * default engine does not (§8.16.2) — and a suite that asserted them would be
 * asserting that the two engines are the same engine, which §8.16.12's
 * capability matrix exists precisely to deny. {@see SearchSchemaTest} asserts
 * §8.16.2's limits against the default driver, where they are a requirement.
 *
 * Ordering is the comparable thing and both engines owe it:
 * {@see DocumentHit::$score} says why a number is not.
 */
final class EngineContractTest extends TestCase
{
    use CommitsSearchDocuments;

    private SearchFixture $fixture;

    private SearchEngine $engine;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->engine = app(SearchEngine::class);

        /*
         * 🛑 An unreachable optional engine is a **skip** locally and a
         * **failure** in CI, which is the `DOCUP_LDAP_E2E` idiom Phase 26b
         * established and for the same reason: a developer without a
         * Meilisearch container should not be blocked, and CI must not report
         * green for a suite that never ran.
         */
        if ($this->engine->driver() === SearchDriver::Meilisearch) {
            /*
             * `getenv()` and not `env()`: Larastan forbids `env()` outside
             * the config directory because it returns null once the config
             * is cached — and a skip that depended on a cached config would
             * be a skip CI could not turn into a failure.
             * `EndToEndBuildTest` reads `DOCUP_E2E` the same way.
             */
            $required = getenv('DOCUP_SEARCH_E2E') === '1';

            if (! $this->engine->isReachable()) {
                if ($required) {
                    $this->fail('DOCUP_SEARCH_E2E=1 but Meilisearch is not reachable');
                }

                $this->markTestSkipped('Meilisearch is not configured; set DOCUP_SEARCH_DRIVER and DOCUP_MEILISEARCH_URL');
            }

            /*
             * §8.16.8's filterable set, before the first document. The index is
             * shared between tests in a run, so the settings call is
             * idempotent and `allowReindex` is true — this is a test index and
             * a reindex of it is free, which is exactly what the production
             * path must not assume.
             */
            /** @var MeilisearchEngine $engine */
            $engine = $this->engine;
            $engine->declareSettings(allowReindex: true);
        }

        $this->fixture = $this->searchFixture('contract');
    }

    protected function tearDown(): void
    {
        $this->forgetEveryIndexedBuild();
        $this->cleanUpCommittedSearchData();

        parent::tearDown();
    }

    /** §8.16.12: "implicit AND between terms". */
    public function test_terms_are_implicitly_anded(): void
    {
        $this->index([
            'html/both.html' => $this->page('Both', 'both', 'This mentions zeta and omega together.'),
            'html/one.html' => $this->page('One', 'one', 'This mentions zeta alone.'),
        ]);

        $both = $this->hrefs($this->search('zeta omega'));

        $this->assertCount(1, $both, 'both terms must be present');
        $this->assertStringContainsString('/both', $both[0]);

        $this->assertCount(2, $this->hrefs($this->search('zeta')), 'one term matches both documents');
    }

    /** §8.16.12: "exact phrase in double quotes". */
    public function test_a_quoted_phrase_is_exact(): void
    {
        $this->index([
            'html/ordered.html' => $this->page('Ordered', 'o', 'The kappa lambda sequence matters.'),
            'html/scrambled.html' => $this->page('Scrambled', 's', 'The lambda and the kappa, apart.'),
        ]);

        $phrase = $this->hrefs($this->search('"kappa lambda"'));

        $this->assertCount(1, $phrase, 'the phrase matches only the document holding it in order');
        $this->assertStringContainsString('/ordered', $phrase[0]);

        $this->assertCount(2, $this->hrefs($this->search('kappa lambda')), 'unquoted, the two terms are ANDed');
    }

    /** §8.16.12's `project:` filter, narrowing to the project in hand. */
    public function test_the_project_scope_filter_narrows(): void
    {
        $this->index(['html/page.html' => $this->page('Page', 'p', 'A document about sigma.')]);

        $this->assertNotSame([], $this->search('project:'.$this->fixture->project->slug.' sigma')->results);

        /*
         * 🛑 A `project:` naming something else narrows to **nothing** rather
         * than reaching across. §8.16.10's cross-project search is Phase 30's
         * deliverable, and an empty result is indistinguishable from "that
         * project has nothing matching" — which is the non-disclosing answer.
         */
        $this->assertSame([], $this->search('project:somebody-else sigma')->results);
    }

    /** §8.16.12's `project:<slug>/<version>` half. */
    public function test_the_version_half_of_the_project_filter_narrows(): void
    {
        $v1 = $this->fixture->version('v1');
        $v2 = $this->fixture->version('v2');

        $this->fixture->publish($v1, ['html/index.html' => $this->page('One', 'a', 'Talking about tau.')]);
        $this->fixture->publish($v2, ['html/index.html' => $this->page('Two', 'b', 'Talking about tau.')]);
        $this->fixture->channels(default: $v1, stable: $v2, latest: $v2);

        app(Indexer::class)->indexProject($this->fixture->project);

        $slug = $this->fixture->project->slug;

        $all = $this->search('tau');
        $this->assertCount(2, $all->results, 'both versions are indexed (§8.16.9)');

        $one = $this->search('project:'.$slug.'/v1 tau');

        $this->assertCount(1, $one->results);
        $this->assertSame('v1', $one->results[0]->versionSlug);
    }

    /** §8.16.12's `self:me`, which is the reader's own accessible set. */
    public function test_the_self_scope_filter_is_honoured(): void
    {
        $this->index(['html/index.html' => $this->page('Page', 'p', 'A document about upsilon.')]);

        $this->assertNotSame([], $this->search('self:me upsilon')->results);
    }

    /**
     * 🛑 §8.16.6's visibility filter, on both engines.
     *
     * The same assertion as exit criterion 2, here because it is part of the
     * contract: an engine that filtered correctly on MySQL and not on
     * Meilisearch would make "switching passes the identical suite" false in
     * the one way that matters.
     */
    public function test_visibility_is_filtered_server_side_on_every_driver(): void
    {
        $public = $this->fixture->version('v-open');
        $private = $this->fixture->version('v-shut', visibility: 'members');

        $this->fixture->publish($public, ['html/index.html' => $this->page('Open', 'o', 'Mentions phigamma.')]);
        $this->fixture->publish($private, ['html/index.html' => $this->page('Shut', 's', 'Mentions phigamma.')]);
        $this->fixture->channels(default: $public, stable: $private, latest: $public);

        app(Indexer::class)->indexProject($this->fixture->project);

        $anonymous = $this->search('phigamma');

        $this->assertCount(1, $anonymous->results);
        $this->assertSame('v-open', $anonymous->results[0]->versionSlug);

        $member = app(SearchQuery::class)->forMount(
            'phigamma',
            $this->fixture->mount('/'),
            ReaderContext::member('contract-reader'),
        );

        $this->assertCount(2, $member->results, 'a member sees both versions');
    }

    /**
     * 🛑 §8.16.3's boost, as an **ordering**.
     *
     * A term in a section's own heading outranks the same term in a body. Both
     * engines express it differently — three FULLTEXT indexes and three weights
     * on one, `searchableAttributes` order on the other — and the ordering is
     * the part they both owe.
     */
    public function test_a_title_match_outranks_a_body_match(): void
    {
        $this->index([
            'html/body.html' => $this->page('Unrelated heading', 'b', 'The body mentions chiterm here.'),
            'html/title.html' => $this->page('Chiterm', 't', 'The body is about something else entirely.'),
        ]);

        $hrefs = $this->hrefs($this->search('chiterm'));

        $this->assertCount(2, $hrefs);
        $this->assertStringContainsString('/title', $hrefs[0], 'the title match comes first');
    }

    /**
     * 🛑 §8.16.3's per-page rank changes the order, on both engines.
     *
     * Read the Docs' own model: a higher rank surfaces a page above an equally
     * good match on a page ranked lower. Asserted as an ordering for the same
     * reason as the title boost.
     */
    public function test_the_page_rank_changes_the_order(): void
    {
        $version = $this->fixture->version('v1');

        $this->fixture->publish($version, [
            'html/index.html' => $this->page('Landing', 'l', 'Nothing of interest.'),
            'html/boosted/index.html' => $this->page('Psiterm', 'a', 'Equal text about psiterm.'),
            'html/demoted/index.html' => $this->page('Psiterm', 'b', 'Equal text about psiterm.'),
        ]);

        $this->fixture->searchConfig($version, [
            'ranking' => ['boosted/*' => 8, 'demoted/*' => -8],
        ]);

        $this->fixture->channels(default: $version, stable: $version, latest: $version);

        app(Indexer::class)->indexProject($this->fixture->project);

        $hrefs = $this->hrefs($this->search('psiterm'));

        $this->assertCount(2, $hrefs);
        $this->assertStringContainsString('/boosted/', $hrefs[0], 'the +8 page ranks above the −8 page');
        $this->assertStringContainsString('/demoted/', $hrefs[1]);
    }

    /** §8.16.5: result URLs are computed, and they are origin-relative. */
    public function test_result_urls_are_computed_from_the_manifest(): void
    {
        $this->index(['html/guide/index.html' => $this->page('Guide', 'install', 'Steps about omicron.')]);

        $hrefs = $this->hrefs($this->search('omicron'));

        $this->assertSame(['/en/v1/guide/#install'], $hrefs);
    }

    /** §8.16.12's degradation rule: an operator-looking query is terms. */
    public function test_an_operator_like_query_degrades_to_terms(): void
    {
        $this->index(['html/index.html' => $this->page('Page', 'p', 'A document about nuterm.')]);

        /*
         * An operator attached to the one term is stripped and the term is
         * searched for — so the reader gets results rather than a validation
         * message.
         */
        foreach (['nuterm*', '+nuterm', '~nuterm', '(nuterm)', '"nuterm"'] as $query) {
            $this->assertNotSame(
                [],
                $this->search($query)->results,
                $query.' must find the document rather than erroring',
            );
        }

        /*
         * 🛑 And a word that **looks** like an operator is a term, which is the
         * honest half of the rule rather than the convenient one.
         *
         * `nuterm OR missingterm` becomes three ANDed terms and `nuterm^5`
         * becomes two — and `missingterm` and `5` are not in the corpus, so the
         * answer is no results. §8.16.12 asks for degradation "to a literal
         * term rather than erroring", not for an engine to grow an `OR` or a
         * boost it does not have; and the test asserts the **state**, because
         * an empty list with `Answered` is a query that ran and found nothing,
         * which is exactly what should have happened.
         *
         * 🛑 Both engines agree on this, which they did not at first:
         * {@see \App\Search\LiteralTerm::wordsOf()} records the divergence.
         */
        foreach (['nuterm OR missingterm', 'nuterm^5'] as $query) {
            $degraded = $this->search($query);

            $this->assertSame([], $degraded->results, $query.' requires every word it reduces to');
            $this->assertSame(
                SearchState::Answered,
                $degraded->state,
                $query.': the engine ran; it just matched nothing',
            );
        }
    }

    /** An empty query answers immediately, with no engine call and no decision. */
    public function test_an_empty_query_is_answered_without_asking_the_engine(): void
    {
        $this->index(['html/index.html' => $this->page('Page', 'p', 'Text.')]);

        $outcome = $this->search('   ');

        $this->assertSame([], $outcome->results);
        $this->assertSame(SearchState::EmptyQuery, $outcome->state);
    }

    /** A project that has never been indexed says so, rather than erroring. */
    public function test_an_unindexed_project_reports_itself(): void
    {
        $version = $this->fixture->version('v1');
        $this->fixture->publish($version, ['html/index.html' => $this->page('Page', 'p', 'Text.')]);
        $this->fixture->channels(default: $version, stable: $version, latest: $version);

        $outcome = $this->search('text');

        $this->assertSame([], $outcome->results);
        $this->assertSame(SearchState::NotIndexed, $outcome->state);
    }

    /**
     * 🛑 §8.16.12's capability matrix exists and claims the three every driver
     * owes.
     *
     * Asserted here rather than in a driver-specific test because it is the
     * contract: a driver that reported one of the three as unsupported would be
     * saying this suite cannot pass on it.
     */
    public function test_the_driver_claims_the_three_required_capabilities(): void
    {
        $capabilities = $this->engine->capabilities();

        foreach (EngineCapability::cases() as $capability) {
            if ($capability->isRequiredOfEveryDriver()) {
                $this->assertTrue(
                    $capabilities->supports($capability),
                    $capability->value.' is required of every driver by §8.16.12',
                );
            } elseif (! $capabilities->supports($capability)) {
                /*
                 * 🛑 And every absence is **documented**, which is the other
                 * half of §8.16.12: "MUST be documented per driver in a
                 * published capability matrix". An unsupported capability with
                 * no note would be a gap a migrating team discovers from a
                 * reader's bug report.
                 */
                $this->assertNotSame(
                    '',
                    $capabilities->note($capability),
                    $capability->value.' is unsupported and must say what happens instead',
                );
            }
        }
    }

    // --------------------------------------------------------------- helpers

    /** @param array<string, string> $files */
    private function index(array $files): void
    {
        $version = $this->fixture->version('v1');

        if (! isset($files['html/index.html'])) {
            $files = ['html/index.html' => $this->page('Index', 'i', 'Landing.')] + $files;
        }

        $this->fixture->publish($version, $files);
        $this->fixture->channels(default: $version, stable: $version, latest: $version);

        app(Indexer::class)->indexProject($this->fixture->project);
    }

    private function search(string $query): SearchOutcome
    {
        return app(SearchQuery::class)->forMount($query, $this->fixture->mount('/'));
    }

    /** @return list<string> */
    private function hrefs(SearchOutcome $outcome): array
    {
        return array_map(
            static fn (SearchResult $result): string => $result->href,
            $outcome->results,
        );
    }

    private function page(string $heading, string $anchor, string $body): string
    {
        return '<!DOCTYPE html><html><head><meta charset="utf-8"><title>T</title></head>'
            .'<body><main><h1 id="page">Page</h1>'
            .'<h2 id="'.$anchor.'">'.$heading.'</h2><p>'.$body.'</p>'
            .'</main></body></html>';
    }

    /**
     * 🛑 Clear the engine's own documents between tests.
     *
     * The default driver's rows go with {@see CommitsSearchDocuments}, which
     * truncates the table. Meilisearch holds its own copy in a **shared index**
     * that no database cleanup touches, so a document from one test would
     * otherwise be found by the next — and the failure would look like a
     * filtering bug.
     */
    private function forgetEveryIndexedBuild(): void
    {
        if ($this->engine->driver() !== SearchDriver::Meilisearch) {
            return;
        }

        $context = app(OrganisationContext::class);
        $context->spanAllOrganisations();

        $rows = DB::table('search_build_index')->get(['build_id', 'generation']);

        foreach ($rows as $row) {
            if (is_string($row->build_id) && Uuid::isBytes($row->build_id)) {
                $this->engine->forgetSections(Uuid::toText($row->build_id), (int) $row->generation);
            }
        }

        $context->forget();
    }
}
