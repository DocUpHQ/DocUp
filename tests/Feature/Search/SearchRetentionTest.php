<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Search;

use App\Search\Indexer;
use App\Search\SearchEngine;
use App\Search\SearchQuery;
use App\Search\SearchRetention;
use App\Support\Uuid;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Tests\Support\CommitsSearchDocuments;
use Tests\TestCase;

/**
 * §8.16.11's retention: batched deletes, and the one thing the sweep must not
 * do.
 *
 * > §8.16.11: "That table is also **unpartitionable** — MySQL supports neither
 * > FULLTEXT indexes nor FULLTEXT search on partitioned tables — so retention
 * > runs as batched deletes rather than `DROP PARTITION`."
 *
 * 🛑 The test that matters here is
 * {@see self::test_a_build_two_projects_mount_is_not_swept_when_one_reindexes()}.
 * The tempting place to delete a superseded generation is at the end of the
 * indexing pass that superseded it, and it is exactly how exit criterion 5
 * breaks: a build mounted by two projects is **one** document set, so project
 * A's reindex would delete the documents project B's live scope rows still
 * point at. Search would work until the second project reindexed, and then half
 * of it would vanish — in production, weeks later, with nothing in the logs.
 */
final class SearchRetentionTest extends TestCase
{
    use CommitsSearchDocuments;

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

    /**
     * 🛑 A build two projects mount survives one of them reindexing.
     *
     * Exit criterion 5's other half: "indexed once … searchable from every
     * project that mounts it" is a claim about retention as much as about
     * extraction.
     */
    public function test_a_build_two_projects_mount_is_not_swept_when_one_reindexes(): void
    {
        $first = $this->searchFixture('ret-a');
        $second = $this->searchFixture('ret-b');

        $origin = $first->version('v1');
        $first->publish($origin, ['html/index.html' => $this->page('sharedretword')]);
        $first->channels(default: $origin, stable: $origin, latest: $origin);

        $buildId = $first->buildIdOf($origin);

        app(Indexer::class)->indexProject($first->project);

        $mounted = $second->version('v9');
        $second->publish($mounted, ['html/index.html' => $this->page('placeholderword')]);
        $second->mountExistingBuild($mounted, $buildId, mountPath: 'docs');
        $second->channels(default: $mounted, stable: $mounted, latest: $mounted);

        app(Indexer::class)->indexProject($second->project);

        /* Project A reindexes. Its generation moves; the shared build does not. */
        app(Indexer::class)->indexProject($first->project);

        $swept = app(SearchRetention::class)->sweep();

        $this->assertSame(
            0,
            $swept['generations'],
            'nothing is orphaned: both projects still point at the shared build',
        );

        $this->assertNotSame(
            [],
            app(SearchQuery::class)->forMount('sharedretword', $second->mount('/'))->results,
            '🛑 and the second project can still find it — the sweep did not take its documents',
        );
    }

    /**
     * A build nobody mounts any more **is** swept.
     *
     * The other direction, because a sweep that never deleted anything would
     * pass the test above and §8.16.11's whole purpose is the deletion.
     */
    public function test_a_build_no_live_scope_row_names_is_swept(): void
    {
        $fixture = $this->searchFixture('ret-c');
        $version = $fixture->version('v1');

        $fixture->publish($version, ['html/index.html' => $this->page('firstretword')]);
        $fixture->channels(default: $version, stable: $version, latest: $version);

        app(Indexer::class)->indexProject($fixture->project);

        $firstBuild = $fixture->buildIdOf($version);

        $this->assertGreaterThan(
            0,
            DB::table('search_documents')->where('build_id', Uuid::toBytes($firstBuild))->count(),
        );

        /* Republish: a new build, and nothing points at the old one. */
        $fixture->publish($version, ['html/index.html' => $this->page('secondretword')]);

        app(Indexer::class)->indexProject($fixture->project);

        $orphans = app(SearchRetention::class)->orphanedGenerations();

        $this->assertSame(
            [$firstBuild],
            array_column($orphans, 0),
            'the superseded build is the orphan, and it is the only one',
        );

        $swept = app(SearchRetention::class)->sweep();

        $this->assertSame(1, $swept['generations']);
        $this->assertGreaterThan(0, $swept['documents']);

        $this->assertSame(
            0,
            DB::table('search_documents')->where('build_id', Uuid::toBytes($firstBuild))->count(),
            'and its documents are gone',
        );

        $this->assertSame(
            0,
            DB::table('search_build_index')->where('build_id', Uuid::toBytes($firstBuild))->count(),
            'with its bookkeeping row',
        );

        /* 🛑 The live build is untouched, which is the half a wrong filter breaks. */
        $this->assertNotSame(
            [],
            app(SearchQuery::class)->forMount('secondretword', $fixture->mount('/'))->results,
        );
    }

    /**
     * 🛑 The delete is **batched**.
     *
     * §8.16.11's reason: the table is unpartitionable, so there is no
     * `DROP PARTITION`, and a single `DELETE` of a 200,000-row generation is a
     * long transaction holding row locks on a §10.9 hot table.
     *
     * Asserted by counting statements rather than by reading the source,
     * because the batch size is a loop condition and a loop that ran once with
     * no `LIMIT` would look identical from outside.
     */
    public function test_the_document_delete_is_batched(): void
    {
        /*
         * A real UUIDv7, not `random_bytes(16)`: `Uuid::toText()` refuses
         * anything that is not a UUID, and this test needs the canonical form
         * to hand the engine.
         */
        $buildId = Uuid::v7();
        $rows = [];

        /* Two and a bit batches, so the loop has to run three times. */
        for ($i = 0; $i < 2_100; $i++) {
            $rows[] = [
                'uuid' => random_bytes(16),
                'build_id' => $buildId,
                'build_generation' => 1,
                'language' => 'en',
                'path' => 'batch/'.$i.'.html',
                'anchor' => 's',
                'title' => 'Batch '.$i,
                'heading_path' => '',
                'page_title' => 'Batch',
                'content' => 'Body '.$i.'.',
                'page_rank' => 0,
                'position' => 0,
                'extracted_from' => 'html',
                'extractor_version' => 1,
                'created_at' => now(),
            ];
        }

        foreach (array_chunk($rows, 700) as $chunk) {
            DB::table('search_documents')->insert($chunk);
        }

        $deletes = 0;

        DB::listen(function (QueryExecuted $query) use (&$deletes): void {
            if (str_starts_with(strtolower(trim($query->sql)), 'delete from `search_documents`')) {
                $deletes++;
            }
        });

        $removed = app(SearchEngine::class)->forgetSections(Uuid::toText($buildId), 1);

        $this->assertSame(2_100, $removed);
        $this->assertGreaterThanOrEqual(
            3,
            $deletes,
            '§8.16.11: 2,100 rows must take more than one statement, or the batch size is not applied',
        );
    }

    /**
     * §8.16.11's measured 28%, reported rather than acted on.
     *
     * The figure comes from `information_schema`, so the assertion is about the
     * shape rather than the value: a fresh table has reclaimed nothing, and the
     * point is that the number exists for an operator to watch.
     */
    public function test_the_table_footprint_is_reportable(): void
    {
        $footprint = app(SearchRetention::class)->tableFootprint();

        $this->assertArrayHasKey('data_bytes', $footprint);
        $this->assertArrayHasKey('index_bytes', $footprint);
        $this->assertArrayHasKey('free_bytes', $footprint);
        $this->assertGreaterThanOrEqual(0.0, $footprint['free_ratio']);
    }

    /**
     * 🛑 `OPTIMIZE TABLE` is **not** scheduled, and this asserts the schedule
     * rather than the comment.
     *
     * §10.9: it "rebuilds and therefore locks, so it belongs in the maintenance
     * window". An application that picked the window itself would pick it wrong
     * on most installations, and the failure is a stall for every reader
     * mid-search and every publish mid-ingest.
     */
    public function test_the_scheduled_retention_run_does_not_optimize(): void
    {
        /*
         * 🛑 Comments stripped, for the reason `ArchitectureTest::code()` gives:
         * this file's own schedule comment TELLS an operator to run
         * `docup:search-retention --optimize` in a maintenance window, and the
         * first version of this assertion failed on that sentence. A test that
         * trips on the documentation of its own rule is testing the prose.
         */
        $schedule = '';

        foreach (token_get_all((string) file_get_contents(base_path('routes/console.php'))) as $token) {
            if (is_array($token)) {
                if (! in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                    $schedule .= $token[1];
                }

                continue;
            }

            $schedule .= $token;
        }

        $this->assertStringContainsString(
            "Schedule::command('docup:search-retention')",
            $schedule,
            'the sweep is scheduled',
        );

        $this->assertStringNotContainsString(
            '--optimize',
            $schedule,
            '🛑 §10.9: the rebuild locks, so it is an operator action and never a schedule',
        );
    }

    private function page(string $term): string
    {
        return '<!DOCTYPE html><html><head><meta charset="utf-8"><title>T</title></head>'
            .'<body><main><h1 id="t">Title</h1><h2 id="s">Section</h2>'
            .'<p>Body mentioning '.$term.' once.</p></main></body></html>';
    }
}
