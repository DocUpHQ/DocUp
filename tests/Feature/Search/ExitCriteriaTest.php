<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Search;

use App\Access\ReaderContext;
use App\Auth\OrganisationContext;
use App\Search\BuildIndexReport;
use App\Search\ExtractedFrom;
use App\Search\Indexer;
use App\Search\SearchOutcome;
use App\Search\SearchQuery;
use App\Search\SearchScopes;
use App\Search\SearchState;
use App\Support\Invalidation;
use App\Support\Uuid;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Tests\Support\CommitsSearchDocuments;
use Tests\Support\SearchFixture;
use Tests\TestCase;

/**
 * 🛑 §17's Phase 29 exit criteria, each asserted rather than described.
 *
 * > "A 5,000-page, three-source project indexes within the §9.2 memory budget
 * > for the indexer and returns correct section anchors from all three sources.
 * > A private version is absent for an anonymous searcher and present for a
 * > member. Republishing bumps the generation with **no window in which both
 * > generations answer**. Switching to Meilisearch passes the identical suite.
 * > 🛑 A reused build is indexed **once** and is searchable from every project
 * > that mounts it, with correct per-project URLs. 🛑 A project whose search
 * > generation lags its policy generation has search **disabled**, not stale."
 *
 * Five of the six are here. The fourth — "switching to Meilisearch passes the
 * identical suite" — is {@see EngineContractTest}, because a criterion about
 * two engines agreeing has to be a suite that runs twice rather than an
 * assertion made once. That file is the suite; CI runs it against a real
 * Meilisearch in its own job, and `DOCUP_SEARCH_E2E=1` turns a skip into a
 * failure there.
 */
final class ExitCriteriaTest extends TestCase
{
    /**
     * 🛑 Not `DatabaseTransactions`, and the trait says why at length: InnoDB
     * FULLTEXT indexes are written at **commit**, so inside a wrapping
     * transaction every document is invisible to `MATCH … AGAINST` while being
     * perfectly visible to a `SELECT`. A search test has to commit.
     */
    use CommitsSearchDocuments;

    private OrganisationContext $context;

    private SearchFixture $fixture;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->context = app(OrganisationContext::class);
        $this->fixture = $this->searchFixture('exit');
    }

    protected function tearDown(): void
    {
        $this->cleanUpCommittedSearchData();

        parent::tearDown();
    }

    // ------------------------------------------------------------------- 1

    /**
     * 🛑 "A 5,000-page, three-source project indexes within the §9.2 memory
     * budget for the indexer and returns correct section anchors from all three
     * sources."
     *
     * Every clause:
     *
     * - **5,000 pages**, published for real and extracted for real.
     * - **Three sources**, composed into one version at three mount paths —
     *   and deliberately one per extraction route, so "all three sources"
     *   holds in both readings: three components, and §8.16.3's HTML route
     *   beside §8.16.4's two structured ones.
     * - **Within §9.2's memory budget.** "Search indexer peak memory: bounded
     *   and declared per driver", measured at "5,000 pages across 3
     *   components". `memory_reset_peak_usage()` runs immediately before the
     *   pass, so the figure is the **indexer's** peak and not the fixture's —
     *   without it the assertion would be about the cost of building a
     *   5,000-entry tar archive, which is not what the budget is about.
     * - **Correct section anchors from all three sources**: a term unique to
     *   each source is searched for, and the anchor and the URL are asserted.
     */
    public function test_a_five_thousand_page_three_source_project_indexes_within_the_memory_budget(): void
    {
        /*
         * 🛑 §9.2's budget, declared here because §9.2 says "bounded and
         * **declared** per driver" and leaves the number to the
         * implementation. 256 MiB is the declaration for the default driver,
         * and the measured figure is printed on failure so the next person can
         * see how much headroom there was rather than guessing.
         */
        $budget = 256 * 1024 * 1024;

        $html = $this->fixture->version('html-src');
        $material = $this->fixture->version('material-src');
        $sphinx = $this->fixture->version('sphinx-src');
        $composed = $this->fixture->version('composed');

        $this->fixture->publish($html, $this->sphinxLikeHtmlTree(3_999, 'alphaunique'));
        $this->fixture->publish($material, $this->materialTree(599, 'bravounique'));
        $this->fixture->publish($sphinx, $this->sphinxJsonTree(399, 'charlieunique'));

        $this->fixture->compose($composed, [
            ['build' => $this->fixture->buildIdOf($html), 'path' => ''],
            ['build' => $this->fixture->buildIdOf($material), 'path' => 'guides'],
            ['build' => $this->fixture->buildIdOf($sphinx), 'path' => 'api'],
        ]);

        $this->fixture->channels(default: $composed, stable: $composed, latest: $composed);

        gc_collect_cycles();
        memory_reset_peak_usage();

        $outcome = app(Indexer::class)->indexProject($this->fixture->project);

        $this->assertSame(1, $outcome->versions, '§8.16.9: one version is all three channels');
        $this->assertSame(3, $outcome->mounts, 'three mounts, one per source');
        $this->assertSame(3, $outcome->buildsIndexed);

        $this->assertLessThanOrEqual(
            $budget,
            $outcome->peakBytes,
            sprintf(
                '§9.2: the indexer peaked at %.1f MiB over 5,000 pages, above the declared %.0f MiB',
                $outcome->peakBytes / 1048576,
                $budget / 1048576,
            ),
        );

        /*
         * 5,000 pages is the criterion's number and it is asserted, not
         * assumed: a fixture that quietly wrote 500 would make the memory
         * figure meaningless.
         */
        $pages = (int) DB::table('search_build_index')->where('state', 'live')->sum('document_count');

        $this->assertSame(5_000, $pages, 'the project really holds 5,000 indexed pages');

        /* 🛑 Each of §8.16.4's and §8.16.3's three routes produced documents. */
        $routes = DB::table('search_build_index')
            ->where('state', 'live')
            ->pluck('extracted_from')
            ->sort()
            ->values()
            ->all();

        $this->assertSame(
            [ExtractedFrom::Html->value, ExtractedFrom::Material->value, ExtractedFrom::Sphinx->value],
            $routes,
            'one source per extraction route, so "all three sources" holds in both readings',
        );

        /* 🛑 Correct section anchors, from all three. */
        $this->assertHit('alphaunique', '/en/composed/page-7/#deep-section', 'the HTML source');
        $this->assertHit('bravounique', '/en/composed/guides/page-3/#install', 'the Material source');
        $this->assertHit('charlieunique', '/en/composed/api/page-2/#reference', 'the Sphinx JSON source');
    }

    // ------------------------------------------------------------------- 2

    /**
     * 🛑 "A private version is absent for an anonymous searcher and present for
     * a member."
     *
     * The same query, the same index, two readers. §8.16.6 makes the filter
     * "server-side only" and this is what that buys: nothing about the request
     * changes except who is asking.
     */
    public function test_a_private_version_is_absent_for_anonymous_and_present_for_a_member(): void
    {
        $public = $this->fixture->version('v-public');
        $private = $this->fixture->version('v-private', visibility: 'members');

        $this->fixture->publish($public, $this->page('publicword', 'open'));
        $this->fixture->publish($private, $this->page('privateword', 'closed'));

        $this->fixture->channels(default: $public, stable: $private, latest: $public);

        app(Indexer::class)->indexProject($this->fixture->project);

        $query = app(SearchQuery::class);
        $mount = $this->fixture->mount('/');

        $anonymous = $query->forMount('privateword', $mount);

        $this->assertSame([], $anonymous->results, 'the members version is absent for an anonymous searcher');

        /*
         * 🛑 And the public version is still searchable in the same breath —
         * otherwise this would pass for a project whose whole index was
         * unreachable, which is a different bug wearing the same result.
         */
        $this->assertNotSame([], $query->forMount('publicword', $mount)->results);

        $member = $query->forMount('privateword', $mount, ReaderContext::member('reader-1'));

        $this->assertNotSame([], $member->results, 'and present for a member');
        $this->assertSame('v-private', $member->results[0]->versionSlug);
        $this->assertStringStartsWith('/en/v-private/', $member->results[0]->href);
    }

    // ------------------------------------------------------------------- 3

    /**
     * 🛑 "Republishing bumps the generation with **no window in which both
     * generations answer**."
     *
     * The second half is the hard part and the only honest way to assert it is
     * to look at what a query can reach **at every point**: before the swap,
     * after the new generation's rows are written but before the pointer moves,
     * and after. §8.16.7's claim is that the middle state answers from the old
     * generation only — not from both, and not from neither.
     *
     * The mechanism is a single `UPDATE` of `projects.search_generation`
     * ({@see Invalidation::advanceSearchGeneration()}), so the proof is that a
     * query matches scope rows **by** that column: the old rows stop being
     * selected by the same statement that starts selecting the new ones.
     */
    public function test_republishing_bumps_the_generation_with_no_window_in_which_both_answer(): void
    {
        $version = $this->fixture->version('v1');
        $this->fixture->publish($version, $this->page('firstword', 'one'));
        $this->fixture->channels(default: $version, stable: $version, latest: $version);

        app(Indexer::class)->indexProject($this->fixture->project);

        $first = (int) DB::table('projects')->where('id', $this->fixture->project->id)->value('search_generation');
        $firstBuild = $this->fixture->buildIdOf($version);

        $this->assertSame(1, $first);
        $this->assertNotSame([], $this->search('firstword')->results);

        /* Republish the same version with different content. */
        $this->fixture->publish($version, $this->page('secondword', 'two'));

        app(Indexer::class)->indexProject($this->fixture->project);

        $second = (int) DB::table('projects')->where('id', $this->fixture->project->id)->value('search_generation');

        $this->assertSame(2, $second, 'republishing bumped the generation');
        $this->assertNotSame($firstBuild, $this->fixture->buildIdOf($version), 'and produced a new build');

        /*
         * The new generation answers and the old one does not. Both halves,
         * because "the generation bumped" with the old documents still
         * reachable would be exactly the window the requirement forbids.
         */
        $this->assertNotSame([], $this->search('secondword')->results, 'the new generation answers');
        $this->assertSame([], $this->search('firstword')->results, 'and the old one does not');

        /*
         * The superseded build's documents are **still in the table**, which is
         * what makes the next assertions mean something: §8.16.11's sweep runs
         * on a schedule and a reused build may still need them, so the only
         * reason they do not answer is that nothing selects them.
         */
        $this->assertGreaterThan(
            0,
            DB::table('search_documents')->where('build_id', Uuid::toBytes($firstBuild))->count(),
            "the superseded build's documents are retained, so what follows is about selection",
        );

        /*
         * 🛑 The window, closed, demonstrated from both sides.
         *
         * A scope row for the OLD build is put back at the OLD generation, so
         * the table now holds both generations in full. With the project
         * pointing at generation 2, generation 1 answers nothing; move the
         * pointer to 1 and the answers swap **completely**. One column decides,
         * and it decides for the whole set at once — which is §8.16.7's "no
         * window in which both generations answer" expressed as the only thing
         * that could falsify it.
         */
        DB::table('search_mount_scopes')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->fixture->organisation->id,
            'project_id' => $this->fixture->project->id,
            'project_version_id' => $version->id,
            'component_mount_id' => null,
            'build_id' => Uuid::toBytes($firstBuild),
            'build_generation' => 1,
            'generation' => $first,
            'scope' => 'public',
            'min_access' => 'public',
            'language' => 'en',
            'channel' => 'default',
            'created_at' => now(),
        ]);

        $this->assertSame([], $this->search('firstword')->results, 'generation 1 exists and does not answer');
        $this->assertNotSame([], $this->search('secondword')->results, 'generation 2 still does');

        /*
         * 🛑 And the swap itself, asserted on the **authorised set** rather than
         * on the results.
         *
         * This is the precise claim: at any one value of
         * `projects.search_generation`, the set of (build, generation) keys a
         * reader may search holds exactly one generation's builds. Moving the
         * pointer replaces that set entirely — it never contains both, which is
         * what "no window in which both generations answer" means.
         *
         * 🛑 Asserted here and not through `search()` because a result also has
         * to have a **URL**, and §8.16.5 computes it from the version's
         * *current* manifest — which names the new build. So the old
         * generation's hit is found by the engine and then correctly discarded
         * by `SearchUrls`, exactly as its docblock says: "the document exists
         * and is no longer reachable at any URL under this version, so offering
         * a link would offer a 404." Asserting on results would therefore pass
         * for the wrong reason, and asserting on the set is the thing the
         * requirement is about.
         */
        $scopes = app(SearchScopes::class);
        $mount = $this->fixture->mount('/');

        $atTwo = array_column($scopes->forMount($mount)->documentKeys(), 0);

        $this->assertSame([$this->fixture->buildIdOf($version)], $atTwo, 'generation 2 names the new build alone');

        DB::table('projects')
            ->where('id', $this->fixture->project->id)
            ->update(['search_generation' => $first]);

        $atOne = array_column($scopes->forMount($this->fixture->mount('/'))->documentKeys(), 0);

        $this->assertSame([$firstBuild], $atOne, 'and generation 1 names the old build alone — never both');
    }

    // ------------------------------------------------------------------- 5

    /**
     * 🛑 "A reused build is indexed **once** and is searchable from every
     * project that mounts it, with correct per-project URLs."
     *
     * Three claims, three assertions:
     *
     * - **Indexed once**: the second project's pass reports the build as
     *   `reused`, and one `search_build_index` row exists for it. Reuse is the
     *   measurable form of the claim — a pass that re-extracted and upserted
     *   would produce the same row counts, which is why
     *   {@see BuildIndexReport::$reused} is a boolean rather than
     *   an inference.
     * - **Searchable from every project**: the same term is found through both
     *   projects' mounts.
     * - **Correct per-project URLs**: the two results carry the two projects'
     *   own hosts' paths, computed at query time from each version's own
     *   manifest (§8.16.5) — including the **mount path**, which differs
     *   between them, so a URL copied from the first project would be visibly
     *   wrong for the second.
     */
    public function test_a_reused_build_is_indexed_once_and_searchable_from_every_project(): void
    {
        $origin = $this->fixture->version('v1');
        $this->fixture->publish($origin, $this->page('sharedword', 'shared'));
        $this->fixture->channels(default: $origin, stable: $origin, latest: $origin);

        $buildId = $this->fixture->buildIdOf($origin);

        $first = app(Indexer::class)->indexProject($this->fixture->project);

        $this->assertSame(1, $first->buildsIndexed);
        $this->assertSame(0, $first->buildsReused);

        /* A second project, mounting the SAME build at a different path. */
        $second = $this->searchFixture('reuse');

        try {
            $other = $second->version('v9');
            $second->publish($other, $this->page('placeholder', 'placeholder'));
            $second->mountExistingBuild($other, $buildId, mountPath: 'docs');
            $second->channels(default: $other, stable: $other, latest: $other);

            $pass = app(Indexer::class)->indexProject($second->project);

            // 🛑 Indexed once: no artifact was read for the shared build.
            $this->assertSame(1, $pass->buildsReused, 'the shared build was reused, not re-extracted');

            $this->assertSame(
                1,
                DB::table('search_build_index')
                    ->where('build_id', Uuid::toBytes($buildId))
                    ->count(),
                'one generation exists for the shared build, not one per mounting project',
            );

            // 🛑 Searchable from both, with each project's own URL.
            $here = $this->search('sharedword');
            $there = app(SearchQuery::class)->forMount('sharedword', $second->mount('/'));

            $this->assertNotSame([], $here->results, 'the origin project finds it');
            $this->assertNotSame([], $there->results, 'and so does the project that mounted it');

            $this->assertSame('/en/v1/#shared', $here->results[0]->href);
            $this->assertSame(
                '/en/v9/docs/#shared',
                $there->results[0]->href,
                '🛑 the mount path differs, so a URL copied from the first project would be wrong',
            );

            $this->assertSame($this->fixture->project->slug, $here->results[0]->projectSlug);
            $this->assertSame($second->project->slug, $there->results[0]->projectSlug);
        } finally {
            $this->context->for($this->fixture->organisation->id);
        }
    }

    // ------------------------------------------------------------------- 6

    /**
     * 🛑 "A project whose search generation lags its policy generation has
     * search **disabled**, not stale."
     *
     * §8.12.21's gate, end to end. The index is built, proven to answer, and
     * then a policy write bumps `policy_generation` past the value the index
     * was built under — and the **same query** stops returning anything, with
     * `SearchState::GenerationStale` naming why.
     *
     * 🛑 "Not stale" is the half that needs asserting. A stale index would keep
     * answering from documents built under the old policy, which is §8.12.21's
     * disclosure: "search returning nothing is an outage, search returning
     * private sections is a disclosure, and only one of those is recoverable."
     */
    public function test_a_project_whose_search_generation_lags_its_policy_generation_has_search_disabled(): void
    {
        $version = $this->fixture->version('v1');
        $this->fixture->publish($version, $this->page('gatedword', 'gated'));
        $this->fixture->channels(default: $version, stable: $version, latest: $version);

        app(Indexer::class)->indexProject($this->fixture->project);

        $before = $this->search('gatedword');

        $this->assertNotSame([], $before->results, 'the index answers before the policy moves');
        $this->assertSame(SearchState::Answered, $before->state);

        /*
         * 🛑 A real policy write, through the one place §10.8 allows an epoch
         * to be bumped. Writing the column by hand would test the comparison
         * and not the wiring — and the wiring is the part that was missing
         * before this phase: `SnapshotProject::$policyGeneration` has been
         * carried since Phase 21 and nothing read it.
         */
        Invalidation::bumpAuthz(
            projectId: $this->fixture->project->id,
            cause: 'policy',
            /*
             * 🛑 `policyWrite: true` is what bumps `policy_generation`;
             * `bumpAuthz` moves `authz_epoch` alone without it. §10.8 gives the
             * two epochs different triggers — "policy, rule, binding,
             * visibility change" for one and "policy write" for the other — and
             * the flag is that distinction. The first version of this test
             * omitted it and asserted that search was disabled when nothing had
             * moved the generation at all.
             */
            policyWrite: true,
            organisationId: $this->fixture->organisation->id,
        );

        $after = $this->search('gatedword');

        $this->assertSame([], $after->results, 'search is disabled while the index lags the policy');
        $this->assertSame(
            SearchState::GenerationStale,
            $after->state,
            '🛑 disabled, and it says so — "nothing matched" would be the same empty list with a different meaning',
        );

        /*
         * 🛑 And the documents are still there. "Disabled, not stale" means the
         * index was not discarded: a reindex brings it back, and nothing had to
         * be rebuilt from artifacts.
         */
        $this->assertGreaterThan(0, DB::table('search_documents')->count());

        app(Indexer::class)->indexProject($this->fixture->project);

        $recovered = $this->search('gatedword');

        $this->assertNotSame([], $recovered->results, 'and a reindex re-enables it');
        $this->assertSame(SearchState::Answered, $recovered->state);
    }

    // --------------------------------------------------------------- helpers

    private function search(string $query): SearchOutcome
    {
        return app(SearchQuery::class)->forMount($query, $this->fixture->mount('/'));
    }

    private function assertHit(string $term, string $expectedHref, string $what): void
    {
        $outcome = $this->search($term);

        $this->assertNotSame([], $outcome->results, $what.' is searchable');
        $this->assertSame($expectedHref, $outcome->results[0]->href, $what."'s anchor and URL are correct");
    }

    /** @return array<string, string> */
    private function page(string $term, string $anchor): array
    {
        return [
            'html/index.html' => '<!DOCTYPE html><html><head><meta charset="utf-8"><title>T</title></head>'
                .'<body><main><h1 id="top">Title</h1>'
                .'<h2 id="'.$anchor.'">Section</h2><p>Body mentioning '.$term.' once.</p>'
                .'</main></body></html>',
        ];
    }

    /** §8.4.5's mandatory landing page. */
    private function landing(string $title): string
    {
        return '<!DOCTYPE html><html><head><meta charset="utf-8"><title>'.$title.'</title></head>'
            .'<body><main><h1 id="t">'.$title.'</h1><p>Landing page.</p></main></body></html>';
    }

    /**
     * §8.16.3's route: a Sphinx-shaped tree with a sidebar on every page.
     *
     * The sidebar is the point. A real Sphinx build repeats its whole table of
     * contents on every page, which is what main-content detection and
     * navigation stripping exist for — a fixture without one would let a broken
     * extractor pass.
     *
     * @return array<string, string>
     */
    private function sphinxLikeHtmlTree(int $pages, string $unique): array
    {
        /*
         * 🛑 §8.4.5 makes `html/index.html` mandatory — "`html/index.html` is
         * mandatory" — and the ingestor refuses a tree without one with
         * `contract.missing_html_index`. Every fixture tree below carries one,
         * which is also what a real generator produces.
         */
        $files = ['html/index.html' => $this->landing('HTML source')];

        for ($i = 0; $i < $pages; $i++) {
            $marker = $i === 7 ? ' '.$unique.' ' : ' ';

            $files['html/page-'.$i.'/index.html'] =
                '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Page '.$i.' — Project</title></head><body>'
                .'<div class="wy-nav-side"><ul><li>Contents of every page</li></ul></div>'
                .'<div role="main"><h1 id="page">Page '.$i.'</h1><p>Lead.</p>'
                .'<section id="deep-section"><h2>Deep section</h2><p>Prose'.$marker.'here.</p></section>'
                .'</div></body></html>';
        }

        return $files;
    }

    /**
     * §8.16.4's Material route: pages plus `search/search_index.json`.
     *
     * @return array<string, string>
     */
    private function materialTree(int $pages, string $unique): array
    {
        $files = ['html/index.html' => $this->landing('Material source')];

        /*
         * The landing page is in the index too, because Material's own plugin
         * indexes it — a fixture that omitted it would make the page count
         * disagree with the published tree, which is how the first run of this
         * test came up two pages short.
         */
        $docs = [['location' => '', 'title' => 'Material source', 'text' => 'Landing page.']];

        for ($i = 0; $i < $pages; $i++) {
            $files['html/page-'.$i.'/index.html'] =
                '<!DOCTYPE html><html><head><meta charset="utf-8"><title>M '.$i.'</title></head>'
                .'<body><main><h1 id="t">M '.$i.'</h1><p>Rendered.</p></main></body></html>';

            $docs[] = ['location' => 'page-'.$i.'/', 'title' => 'M '.$i, 'text' => 'Page '.$i.' overview.'];
            $docs[] = [
                'location' => 'page-'.$i.'/#install',
                'title' => 'Install',
                'text' => 'Installation steps'.($i === 3 ? ' '.$unique : '').'.',
            ];
        }

        $files['html/search/search_index.json'] = (string) json_encode(['config' => [], 'docs' => $docs]);

        return $files;
    }

    /**
     * §8.16.4's Sphinx route: `.fjson` pages beside a `globalcontext.json`.
     *
     * @return array<string, string>
     */
    private function sphinxJsonTree(int $pages, string $unique): array
    {
        $files = [
            'html/index.html' => $this->landing('Sphinx JSON source'),
            'html/_json/globalcontext.json' => '{"project":"Fixture"}',
            'html/_json/index.fjson' => (string) json_encode([
                'current_page_name' => 'index',
                'title' => 'Sphinx JSON source',
                'body' => '<section id="landing"><h2>Landing</h2><p>Landing page.</p></section>',
            ]),
        ];

        for ($i = 0; $i < $pages; $i++) {
            $files['html/page-'.$i.'/index.html'] =
                '<!DOCTYPE html><html><head><meta charset="utf-8"><title>S '.$i.'</title></head>'
                .'<body><main><h1 id="t">S '.$i.'</h1><p>Rendered.</p></main></body></html>';

            $files['html/_json/page-'.$i.'/index.fjson'] = (string) json_encode([
                'current_page_name' => 'page-'.$i.'/index',
                'title' => 'S '.$i,
                'body' => '<section id="reference"><h2>Reference</h2><p>Details'
                    .($i === 2 ? ' '.$unique : '').'.</p></section>',
            ]);
        }

        return $files;
    }
}
