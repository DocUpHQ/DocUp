<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Search;

use App\Search\EngineLimits;
use App\Search\Engines\MysqlFulltextEngine;
use App\Search\SearchDriver;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * 🛑 §9.1.3, §8.16.11 and §8.16.2 against the **running server**.
 *
 * `ArchitectureTest::test_only_the_allowlisted_auto_increment_exists()` scans
 * migration source and is the right shape for a rule about what DocUp writes.
 * It cannot see three things this file can, and §9.1.3 names one of them
 * explicitly:
 *
 * > "InnoDB additionally maintains a hidden `FTS_DOC_ID` and its own
 * > `FTS_DOC_ID_INDEX` on that table; neither is declared by DocUp, and the
 * > architecture test must not mistake them for a violation (ADR 0004)."
 *
 * A source scan cannot mistake them for anything — it never sees them. A test
 * against `information_schema` would, which is exactly why that test has to
 * exist and has to be written knowing it: ADR 0004's whole finding is that
 * declaring `FTS_DOC_ID` breaks bulk inserts with `ERROR 182`, so the
 * invariant worth asserting is that it is **absent from the declared schema
 * and still working**.
 *
 * §8.16.2's figures are here for the same reason. The requirement states "a
 * three-character minimum token, 36 default stopwords", and the honest way to
 * claim a server default is to read it off a server rather than to quote it.
 */
final class SearchSchemaTest extends TestCase
{
    /**
     * 🛑 §9.1.3: exactly one AUTO_INCREMENT in the live schema, and it is the
     * one §8.16.11 names.
     *
     * The framework's own tables are allowlisted by name, as
     * `SchemaConformanceTest` already does for `$frameworkTables` and for the
     * same reason: `jobs.id` is part of Laravel's queue driver contract and
     * `migrations.id` is the framework's own bookkeeping. Neither is part of
     * DocUp's data model and neither is reachable from a migration this project
     * wrote.
     */
    public function test_search_documents_carries_the_only_docup_auto_increment(): void
    {
        $framework = ['jobs', 'job_batches', 'failed_jobs', 'migrations', 'sessions'];

        /** @var list<object{TABLE_NAME: string, COLUMN_NAME: string}> $rows */
        $rows = DB::select(
            "SELECT TABLE_NAME, COLUMN_NAME FROM information_schema.COLUMNS
              WHERE TABLE_SCHEMA = DATABASE() AND EXTRA LIKE '%auto_increment%'
              ORDER BY TABLE_NAME, COLUMN_NAME",
        );

        $this->assertNotEmpty($rows, 'has the test database been migrated?');

        $docup = [];

        foreach ($rows as $row) {
            if (! in_array($row->TABLE_NAME, $framework, true)) {
                $docup[] = $row->TABLE_NAME.'.'.$row->COLUMN_NAME;
            }
        }

        $this->assertSame(
            ['search_documents.id'],
            $docup,
            '§9.1.3 allows exactly one AUTO_INCREMENT in DocUp\'s schema: the §8.16.11 surrogate',
        );
    }

    /**
     * 🛑 §9.1.3 and ADR 0004: `FTS_DOC_ID` is InnoDB's, hidden, and undeclared.
     *
     * > §8.16.11: "~~The table MUST declare that column explicitly rather than
     * > rely on the hidden one.~~ **FAILED (Phase 00, 2026-10-19)** — declaring
     * > `FTS_DOC_ID` while a FULLTEXT index exists makes bulk `INSERT … SELECT`
     * > fail with `ERROR 182 (HY000) Invalid InnoDB FTS Doc ID`."
     *
     * So the assertion is a **pair**: the column is absent from the declared
     * schema, and a bulk insert of the kind that would have failed succeeds.
     * Asserting only the absence would leave the reason for it as a comment,
     * and a later release could re-declare it and still pass.
     */
    public function test_the_hidden_fts_doc_id_is_absent_and_bulk_inserts_work(): void
    {
        /** @var list<object{COLUMN_NAME: string}> $columns */
        $columns = DB::select(
            'SELECT COLUMN_NAME FROM information_schema.COLUMNS
              WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?',
            ['search_documents'],
        );

        $names = array_map(static fn (object $row): string => strtoupper($row->COLUMN_NAME), $columns);

        $this->assertNotContains(
            'FTS_DOC_ID',
            $names,
            'ADR 0004: declaring FTS_DOC_ID breaks bulk inserts with ERROR 182. InnoDB manages it hidden.',
        );

        /** @var list<object{INDEX_NAME: string}> $indexes */
        $indexes = DB::select(
            'SELECT DISTINCT INDEX_NAME FROM information_schema.STATISTICS
              WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?',
            ['search_documents'],
        );

        $this->assertNotContains(
            'FTS_DOC_ID_INDEX',
            array_map(static fn (object $row): string => strtoupper($row->INDEX_NAME), $indexes),
            '§9.1.3: InnoDB maintains its own index on the hidden column; DocUp declares neither',
        );

        /*
         * 🛑 The insert ADR 0004 measured failing. 600 rows in one statement is
         * well past the point a declared `FTS_DOC_ID` would have refused — the
         * failure is on the first multi-row insert, not at scale — and it is
         * the shape `MysqlFulltextEngine::writeSections()` actually uses.
         */
        $buildId = random_bytes(16);
        $rows = [];

        for ($i = 0; $i < 600; $i++) {
            $rows[] = [
                'uuid' => random_bytes(16),
                'build_id' => $buildId,
                'build_generation' => 1,
                'language' => 'en',
                'path' => 'bulk/'.$i.'.html',
                'anchor' => 'section-'.$i,
                'title' => 'Bulk '.$i,
                'heading_path' => '',
                'page_title' => 'Bulk',
                'content' => 'Representative body text for row '.$i.'.',
                'page_rank' => 0,
                'position' => $i,
                'extracted_from' => 'html',
                'extractor_version' => 1,
                'created_at' => now(),
            ];
        }

        DB::table('search_documents')->insert($rows);

        $this->assertSame(
            600,
            DB::table('search_documents')->where('build_id', $buildId)->count(),
            'a 600-row single-statement insert succeeds, which is what ADR 0004 says the hidden column allows',
        );

        DB::table('search_documents')->where('build_id', $buildId)->delete();
    }

    /**
     * 🛑 §8.16.3's three boost levels are three FULLTEXT indexes.
     *
     * MySQL permits `MATCH(title)` only with an index on exactly `(title)`, so
     * the three columns §8.16.3 boosts need three indexes and there is no
     * per-field weight to use instead. Asserted by name because
     * `MysqlFulltextEngine::search()` writes three `MATCH` expressions and a
     * missing index makes it fail at query time with a message about the
     * expression rather than the schema.
     */
    public function test_the_three_fulltext_indexes_exist(): void
    {
        /** @var list<object{INDEX_NAME: string, INDEX_TYPE: string}> $rows */
        $rows = DB::select(
            'SELECT DISTINCT INDEX_NAME, INDEX_TYPE FROM information_schema.STATISTICS
              WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_TYPE = ?
              ORDER BY INDEX_NAME',
            ['search_documents', 'FULLTEXT'],
        );

        $this->assertSame(
            [
                'search_documents_ft_all',
                'search_documents_ft_heading',
                'search_documents_ft_title',
            ],
            array_map(static fn (object $row): string => $row->INDEX_NAME, $rows),
        );
    }

    /**
     * 🛑 §8.16.11: no foreign keys on `search_documents`, "because the retention
     * sweep must not cascade".
     *
     * A cascade from `builds` would turn one artifact reap into an unbatched
     * delete of a whole generation inside somebody else's transaction, on a
     * §10.9 hot table — which is exactly the thing §8.16.11's batched deletes
     * exist to avoid.
     */
    public function test_search_documents_carries_no_foreign_keys(): void
    {
        /** @var list<object{CONSTRAINT_NAME: string}> $rows */
        $rows = DB::select(
            'SELECT CONSTRAINT_NAME FROM information_schema.TABLE_CONSTRAINTS
              WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND CONSTRAINT_TYPE = ?',
            ['search_documents', 'FOREIGN KEY'],
        );

        $this->assertSame([], $rows, '§8.16.11 declines foreign keys here; the sweep must not cascade');
    }

    /**
     * 🛑 §8.16.2's figures, measured rather than quoted.
     *
     * > "no stemming, no typo tolerance, a three-character minimum token, 36
     * > default stopwords"
     *
     * If a MySQL release changes either default, this test says so and the
     * build log records it — rather than the product UI confidently printing a
     * number the server disagrees with, which is the failure §8.16.2 exists to
     * prevent in the first place.
     */
    public function test_the_servers_fulltext_defaults_are_the_ones_8_16_2_states(): void
    {
        $limits = (new MysqlFulltextEngine)->limits();

        $this->assertSame(SearchDriver::MysqlFulltext, $limits->driver);

        $this->assertSame(
            EngineLimits::SPEC_MIN_TOKEN_SIZE,
            $limits->minTokenSize,
            '§8.16.2 states a three-character minimum token; this server disagrees',
        );

        $this->assertSame(
            EngineLimits::SPEC_STOPWORD_COUNT,
            $limits->stopwordCount,
            '§8.16.2 states 36 default stopwords; this server disagrees',
        );

        $this->assertFalse($limits->stemming, '§8.16.2: no stemming');
        $this->assertFalse($limits->typoTolerance, '§8.16.2: no typo tolerance');
    }

    /**
     * 🛑 §8.16.2's illustration leads with a **two**-character term.
     *
     * > "The illustration must use a **two**-character term … while `go` returns
     * > **0** … 'Why can't I find `go`?' is the real first support question
     * > (ADR 0004)."
     *
     * Asserted as an ordering property of the published list, because the
     * requirement is about what an operator reads first. A UI that led with
     * `api` would be technically complete and would answer the wrong question.
     */
    public function test_the_published_illustration_leads_with_a_two_character_term(): void
    {
        $illustrations = (new MysqlFulltextEngine)->limits()->illustrations();

        $this->assertSame('go', $illustrations[0]['term']);
        $this->assertSame(2, mb_strlen($illustrations[0]['term']));
        $this->assertSame('no results', $illustrations[0]['outcome']);
        $this->assertTrue($illustrations[0]['live'], 'the two-character case is read from this server, not quoted');

        $terms = array_column($illustrations, 'term');

        $this->assertSame(['go', 'the', 'authentcation', 'deploying', 'api'], $terms, '§8.16.2 names all five');

        /*
         * 🛑 The one illustration that is a **measurement** says so. ADR 0004's
         * "`api` returns 100,000 hits at 200,000 sections" cannot be re-measured
         * by a UI render, and presenting it as a live reading would be the kind
         * of over-claim §8.16.2's own precision is guarding against.
         */
        $api = $illustrations[4];

        $this->assertFalse($api['live']);
        $this->assertStringContainsString('200,000', $api['why']);
        $this->assertStringContainsString('ADR 0004', $api['why']);
    }

    /**
     * 🛑 §8.16.2's stated behaviour, against the real index.
     *
     * Not an illustration this time — the actual queries. `go` is below the
     * minimum token size, `the` is a stopword, `authentcation` is a typo and
     * `deploying` is not a stem of `deploy`. Four facts, and the product UI
     * claims all four, so all four are asserted against a FULLTEXT index that
     * genuinely holds the words.
     */
    public function test_the_default_engines_limits_are_real(): void
    {
        $buildId = random_bytes(16);

        DB::table('search_documents')->insert([
            'uuid' => random_bytes(16),
            'build_id' => $buildId,
            'build_generation' => 1,
            'language' => 'en',
            'path' => 'limits.html',
            'anchor' => null,
            'title' => 'Deploy the go toolchain',
            'heading_path' => '',
            'page_title' => 'Limits',
            'content' => 'The authentication guide explains how to deploy with go and the api.',
            'page_rank' => 0,
            'position' => 0,
            'extracted_from' => 'html',
            'extractor_version' => 1,
            'created_at' => now(),
        ]);

        $matches = function (string $term) use ($buildId): int {
            /** @var list<object{n: int|string}> $rows */
            $rows = DB::select(
                'SELECT COUNT(*) AS n FROM search_documents
                  WHERE build_id = ?
                    AND MATCH (title, heading_path, content) AGAINST (? IN BOOLEAN MODE)',
                [$buildId, '+'.$term],
            );

            return (int) $rows[0]->n;
        };

        $this->assertSame(0, $matches('go'), '§8.16.2: two characters is below innodb_ft_min_token_size');
        $this->assertSame(0, $matches('the'), '§8.16.2: a stopword');
        $this->assertSame(0, $matches('authentcation'), '§8.16.2: no typo tolerance');
        $this->assertSame(0, $matches('deploying'), '§8.16.2: no stemming — `deploying` does not match `deploy`');

        // And the control: three characters, not a stopword, spelled correctly.
        $this->assertSame(1, $matches('api'), 'three characters clears the minimum');
        $this->assertSame(1, $matches('deploy'), 'the word itself matches');

        DB::table('search_documents')->where('build_id', $buildId)->delete();
    }
}
