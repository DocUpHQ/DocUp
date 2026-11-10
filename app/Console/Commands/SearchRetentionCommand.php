<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Search\SearchRetention;
use Illuminate\Console\Command;

/**
 * `docup:search-retention` — §8.16.11's batched deletes and §10.9's scheduled
 * `OPTIMIZE TABLE`.
 *
 * ## 🛑 The sweep runs; the rebuild is asked for
 *
 * §8.16.11 requires both, and they belong in different hands. The sweep is a
 * bounded series of batched deletes with no lock worth mentioning, so
 * `routes/console.php` schedules it. `OPTIMIZE TABLE` "rebuilds and therefore
 * locks" (§10.9) on a table §10.9 names hot — so it reports what it would
 * reclaim and does the work only when `--optimize` is passed.
 *
 * An application that chose its own maintenance window would choose it wrong on
 * most installations, and the failure is a stall for every reader mid-search
 * and every publish mid-ingest.
 */
final class SearchRetentionCommand extends Command
{
    protected $signature = 'docup:search-retention
        {--optimize : Run OPTIMIZE TABLE on search_documents. It LOCKS: maintenance window only (§10.9)}';

    protected $description = 'Sweep orphaned search document generations and report reclaimable space (§8.16.11)';

    public function handle(SearchRetention $retention): int
    {
        $swept = $retention->sweep();

        $this->line(sprintf(
            '  swept %d orphaned build generations, %d documents deleted',
            $swept['generations'],
            $swept['documents'],
        ));

        $footprint = $retention->tableFootprint();

        $this->line(sprintf(
            '  search_documents: %.1f MiB data, %.1f MiB index, %.1f MiB reclaimable (%.1f%%)',
            $footprint['data_bytes'] / 1048576,
            $footprint['index_bytes'] / 1048576,
            $footprint['free_bytes'] / 1048576,
            $footprint['free_ratio'] * 100,
        ));

        /*
         * 🛑 §8.16.11's measured number, as the threshold for mentioning it.
         * "50 republish cycles grew the index by 28% and it plateaued there
         * rather than reclaiming, with only `OPTIMIZE TABLE` recovering the
         * space." So 28% is not a limit being approached — it is where the
         * growth stops — and an operator seeing it should know it will not get
         * better on its own.
         */
        if ($footprint['free_ratio'] >= 0.20) {
            $this->components->warn(
                'Reclaimable space is above 20%. §8.16.11 measured this plateauing near 28% rather than '
                .'recovering: only OPTIMIZE TABLE returns it, and it locks the table while it rebuilds. '
                .'Run with --optimize inside a maintenance window.',
            );
        }

        if ((bool) $this->option('optimize')) {
            $this->line('  OPTIMIZE TABLE search_documents — this locks the table');
            $retention->optimize();
            $this->line('  done');
        }

        return self::SUCCESS;
    }
}
