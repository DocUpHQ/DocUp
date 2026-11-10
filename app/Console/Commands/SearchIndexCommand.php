<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Auth\OrganisationContext;
use App\Models\Project;
use App\Search\Engines\MeilisearchEngine;
use App\Search\Indexer;
use App\Search\SearchDriver;
use App\Search\SearchEngine;
use App\Search\SearchRefused;
use App\Search\SectionExtractor;
use App\Support\Uuid;
use Illuminate\Console\Command;

/**
 * `docup:search-index` — §8.16's indexing pass, and how an operator reaches it.
 *
 * ## 🛑 Why indexing is a command and not a hook on publish
 *
 * The obvious wiring is "republish, then index", and §8.16.7 even says
 * "Republishing MUST bump the generation". It is still the wrong shape for this
 * phase, for three reasons stated here rather than discovered later:
 *
 * 1. **A build is shared.** §8.16.5 makes a reused build one document set
 *    across every project that mounts it, so indexing is per **project**, and a
 *    publish into one project's version changes what two other projects should
 *    serve. A hook on publish would run the wrong pass.
 * 2. **§9.2 budgets the indexer, not the publisher.** A 5,000-page pass is
 *    seconds of CPU and tens of megabytes; inside a publish it would be inside
 *    the compare-and-swap transaction §8.8.4 requires to be a single row
 *    update.
 * 3. **§8.12.21's gate makes a lagging index safe.** Search is disabled rather
 *    than stale, so an index that has not caught up is an outage of search and
 *    not a disclosure — which is exactly the property that lets indexing be
 *    asynchronous at all.
 *
 * So this command is the entry point, `routes/console.php` schedules it, and
 * §17's Phase 30 owns the reader-facing surface that makes the freshness
 * visible.
 *
 * ## 🛑 `--force` re-reads every artifact
 *
 * Without it, a build already indexed at the current
 * {@see SectionExtractor::VERSION} is skipped and no artifact byte
 * is read — which is §8.16.5's "indexed once". `--force` is the escape hatch
 * for a corrupted index and it costs a full re-extraction of every build in
 * every project it touches. Said out loud because the flag is one word and the
 * cost is not.
 */
final class SearchIndexCommand extends Command
{
    protected $signature = 'docup:search-index
        {--project= : Limit to one project, by slug or UUID}
        {--force : Re-extract every build even if it is already indexed at this extractor version}
        {--limit=0 : Stop after this many projects (0 means no limit)}';

    protected $description
        = 'Index the default, stable and latest versions of every project for §8.16 search';

    public function handle(Indexer $indexer, SearchEngine $engine, OrganisationContext $context): int
    {
        $this->line('  <options=bold>DocUp search index</>');
        $this->line('  engine: '.$engine->driver()->label());

        /*
         * 🛑 The index's settings before the first document. §8.16.8's
         * filterable set must be declared before anything is written, because
         * Meilisearch will not filter on an attribute it was not told about —
         * and a pass that wrote 200,000 documents first would then need the
         * full reindex §8.16.8 exists to avoid.
         *
         * A refusal here is {@see \App\Search\SearchRejection::FilterSetChanged}
         * and it stops the command: §8.16.8 calls that "a migration event", so
         * it is an operator's decision and not a thing the pass performs on its
         * own.
         */
        if ($engine instanceof MeilisearchEngine) {
            try {
                $engine->declareSettings();
            } catch (SearchRefused $refused) {
                $this->components->error($refused->identifier().' — '.$refused->rejection->reason());
                $this->line('  Run with DOCUP_SEARCH_DRIVER unset to use the default engine, or reindex deliberately.');

                return self::FAILURE;
            }
        }

        if (! $engine->isReachable()) {
            $this->components->error(
                $engine->driver()->label().' is not reachable. Nothing was indexed.',
            );

            return self::FAILURE;
        }

        $projects = $this->projects($context);

        if ($projects === []) {
            $this->components->warn('No projects matched.');

            return self::SUCCESS;
        }

        $limit = max(0, (int) $this->option('limit'));
        $force = (bool) $this->option('force');

        $done = 0;
        $sections = 0;
        $reused = 0;
        $peak = 0;

        foreach ($projects as $project) {
            if ($limit > 0 && $done >= $limit) {
                break;
            }

            $outcome = $indexer->indexProject($project, $force);
            $done++;
            $sections += $outcome->sections;
            $reused += $outcome->buildsReused;
            $peak = max($peak, $outcome->peakBytes);

            $this->line(sprintf('  %-40s %s', (string) $project->slug, $outcome->summary()));
        }

        $this->newLine();
        $this->line(sprintf(
            '  %d projects, %d sections live, %d builds reused rather than re-read, peak %.1f MiB',
            $done,
            $sections,
            $reused,
            $peak / 1048576,
        ));

        /*
         * 🛑 §8.16.1's threshold, reported where the operator is already
         * looking. `doctor` carries the same warning; printing it here too
         * means the person who just grew the corpus past the threshold learns
         * it at the moment they did, rather than the next time somebody runs
         * `doctor`.
         */
        $this->reportThreshold($engine);

        return self::SUCCESS;
    }

    /**
     * The projects to index.
     *
     * 🛑 `acrossAllOrganisations`, because this is an installation-wide
     * operator action with no tenant of its own — and {@see Indexer} declares
     * each project's tenant with `withinOrganisation()` before touching
     * anything. §8.2.1's global scope would otherwise make this command index
     * nothing at all, silently, which is the shape of failure
     * `OrganisationContext` exists to prevent.
     *
     * @return list<Project>
     */
    private function projects(OrganisationContext $context): array
    {
        $slug = $this->option('project');

        /** @var list<Project> */
        return $context->acrossAllOrganisations(function () use ($slug): array {
            $query = Project::query()->orderBy('slug');

            if (is_string($slug) && $slug !== '') {
                $bytes = Uuid::tryToBytes($slug);

                if ($bytes !== null) {
                    $query->whereKey($bytes);
                } else {
                    $query->where('slug', $slug);
                }
            }

            return $query->get()->all();
        });
    }

    /** §8.16.1's "doctor warning at the threshold", in the indexer's own output. */
    private function reportThreshold(SearchEngine $engine): void
    {
        $threshold = config('docup.search.meilisearch_recommended_above_sections');
        $threshold = is_numeric($threshold) ? (int) $threshold : 200_000;
        $count = $engine->sectionCount();

        if ($engine->driver() === SearchDriver::MysqlFulltext && $count > $threshold) {
            $this->components->warn(sprintf(
                'The index holds about %s sections, above §8.16.1\'s %s threshold. '
                .'Meilisearch is recommended above this size: §8.16.6 measured the filtered query at p95 80 ms '
                .'against 10 ms unfiltered, and the cost scales with match-set size rather than result limit.',
                number_format($count),
                number_format($threshold),
            ));
        }
    }
}
