<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

use App\Auth\OrganisationContext;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 §8.16.11's retention: batched deletes, and the `OPTIMIZE TABLE` they make
 * necessary.
 *
 * > §8.16.11: "That table is also **unpartitionable** — MySQL supports neither
 * > FULLTEXT indexes nor FULLTEXT search on partitioned tables — so retention
 * > runs as batched deletes rather than `DROP PARTITION`, and 🛑 a **scheduled
 * > `OPTIMIZE TABLE`** is required: 50 republish cycles grew the index by 28%
 * > and it plateaued there rather than reclaiming, with only `OPTIMIZE TABLE`
 * > recovering the space."
 *
 * Two jobs, and they are separate because they fail differently.
 *
 * ## 🛑 The sweep: why a build's documents are not deleted when its project reindexes
 *
 * The tempting place to delete a superseded generation is at the end of the
 * indexing pass that superseded it. It would be wrong, and it is exactly how
 * exit criterion 5 breaks: a build mounted by two projects is **one** document
 * set, so project A's reindex superseding generation 3 for that build would
 * delete the documents project B's live scope rows still point at. Search would
 * work until the second project reindexed, and then half of it would vanish.
 *
 * So the sweep deletes a (build, generation) only when **no live scope row in
 * any project** names it. That is a question about the whole installation,
 * which is why this runs on a schedule rather than inside a pass, and why it
 * reads across organisations.
 *
 * ## 🛑 `OPTIMIZE TABLE` locks, so it is not run from here automatically
 *
 * §10.9: "`OPTIMIZE TABLE` rebuilds and therefore locks, so it belongs in the
 * maintenance window". The scheduled command **reports** the reclaimable space
 * and runs the rebuild only when told to — an operator's maintenance window is
 * not something an application picks for them, and a surprise table rebuild on
 * a §10.9 hot table during business hours is a worse outage than 28% of wasted
 * index space.
 */
final readonly class SearchRetention
{
    /** Rows per delete statement — §8.16.11's "batched". */
    public const int BATCH = 1_000;

    /** Build generations retired per sweep run. */
    public const int MAX_GENERATIONS_PER_RUN = 200;

    public function __construct(
        private SearchEngine $engine,
        private OrganisationContext $context,
    ) {}

    /**
     * Delete every document set no live scope row points at.
     *
     * @return array{generations: int, documents: int}
     */
    public function sweep(): array
    {
        $orphans = $this->orphanedGenerations();
        $documents = 0;

        foreach ($orphans as [$buildId, $generation]) {
            $documents += $this->engine->forgetSections($buildId, $generation);

            DB::table('search_build_index')
                ->where('build_id', Uuid::tryToBytes($buildId) ?? str_repeat("\xff", 16))
                ->where('generation', $generation)
                ->delete();
        }

        return ['generations' => count($orphans), 'documents' => $documents];
    }

    /**
     * (build, generation) pairs that no live scope row names.
     *
     * 🛑 "Live" means `generation = projects.search_generation`, which is the
     * same predicate the query path uses — so a pair this method calls orphaned
     * is a pair no reader can reach. The join to `projects` is what makes that
     * true rather than nearly true: a scope row from a superseded project
     * generation is not live even though it exists.
     *
     * Read across organisations because a reused build spans them: §8.7.1 makes
     * a component organisation-owned and mountable by any project version with
     * a grant, so "is anything still using this build" is an
     * installation-wide question by construction.
     *
     * @return list<array{0: string, 1: int}>
     */
    public function orphanedGenerations(): array
    {
        /** @var list<array{0: string, 1: int}> */
        return $this->context->acrossAllOrganisations(function (): array {
            $rows = DB::table('search_build_index as b')
                ->leftJoin('search_mount_scopes as s', function ($join): void {
                    $join->on('s.build_id', '=', 'b.build_id')
                        ->on('s.build_generation', '=', 'b.generation');
                })
                ->leftJoin('projects as p', 'p.id', '=', 's.project_id')
                /*
                 * A scope row only counts when it is its project's live
                 * generation. `whereColumn` inside the join would make the
                 * join itself conditional, which reads the same and is not:
                 * the row would be excluded from the join rather than from
                 * "counts as a reference", and the GROUP BY below would then
                 * see a NULL for a build that IS referenced.
                 */
                ->selectRaw('b.build_id, b.generation, SUM(CASE WHEN s.id IS NOT NULL AND s.generation = p.search_generation THEN 1 ELSE 0 END) AS live_refs')
                ->groupBy('b.build_id', 'b.generation')
                ->havingRaw('live_refs = 0')
                ->orderBy('b.build_id')
                ->orderBy('b.generation')
                ->limit(self::MAX_GENERATIONS_PER_RUN)
                ->get();

            $orphans = [];

            foreach ($rows as $row) {
                if (! is_string($row->build_id) || ! Uuid::isBytes($row->build_id)) {
                    continue;
                }

                $orphans[] = [Uuid::toText($row->build_id), (int) $row->generation];
            }

            return $orphans;
        });
    }

    /**
     * 🛑 §8.16.11's measured 28%: how much of the table is reclaimable.
     *
     * `DATA_FREE` from `information_schema` — the space InnoDB has released
     * inside the tablespace and will reuse but not return. §8.16.11 measured it
     * plateauing at roughly +28% over 50 republish cycles, which is the number
     * an operator needs to decide whether a maintenance window is worth
     * booking.
     *
     * @return array{data_bytes: int, index_bytes: int, free_bytes: int, free_ratio: float}
     */
    public function tableFootprint(): array
    {
        /** @var object{d: int|string|null, i: int|string|null, f: int|string|null}|null $row */
        $row = DB::selectOne(
            'SELECT DATA_LENGTH AS d, INDEX_LENGTH AS i, DATA_FREE AS f
               FROM information_schema.TABLES
              WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?',
            ['search_documents'],
        );

        $data = $row !== null && is_numeric($row->d) ? (int) $row->d : 0;
        $index = $row !== null && is_numeric($row->i) ? (int) $row->i : 0;
        $free = $row !== null && is_numeric($row->f) ? (int) $row->f : 0;
        $used = $data + $index;

        return [
            'data_bytes' => $data,
            'index_bytes' => $index,
            'free_bytes' => $free,
            'free_ratio' => $used > 0 ? $free / $used : 0.0,
        ];
    }

    /**
     * 🛑 §8.16.11's scheduled `OPTIMIZE TABLE`, run only when asked.
     *
     * §10.9 puts it in the maintenance window because it "rebuilds and
     * therefore locks". On a §10.9 hot table that is a stall for every reader
     * mid-search and every publish mid-ingest, so the scheduled command
     * **reports** {@see self::tableFootprint()} and an operator passes
     * `--optimize` when they have a window. An application that picked the
     * window itself would be picking it wrong on most installations.
     *
     * InnoDB maps `OPTIMIZE TABLE` to `ALTER TABLE … FORCE` and says so on
     * stderr; the note is expected and is not an error.
     */
    public function optimize(): void
    {
        DB::statement('OPTIMIZE TABLE `search_documents`');
    }
}
