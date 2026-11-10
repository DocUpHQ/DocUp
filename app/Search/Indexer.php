<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

use App\Artifacts\ArtifactStore;
use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Serving\ManifestReader;
use App\Support\Invalidation;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 One indexing pass over one project: §8.16.5, §8.16.7 and §8.16.9 in one
 * place.
 *
 * ## The shape of a pass
 *
 * 1. Read `policy_generation` **first**, and remember it.
 * 2. Choose the versions §8.16.9 permits — `default`, `stable`, `latest`, and
 *    nothing hidden or inactive.
 * 3. For each version's published manifest, for each mount: index the build
 *    behind it, **unless it is already indexed** (§8.16.5's "indexed once").
 * 4. Write the new generation's scope rows.
 * 5. Swap: one `UPDATE` moves `search_generation`, which is the moment the new
 *    generation starts answering and the old one stops.
 * 6. Sweep the superseded rows in batches.
 *
 * ## 🛑 Why `policy_generation` is read first and not last
 *
 * §8.12.21 disables search while the index lags the policy. The index reflects
 * the policy as it was **when the pass started reading** — a policy write
 * halfway through a 5,000-page pass is not in the half already written. So the
 * value recorded is the one observed before step 2, and a concurrent policy
 * write therefore leaves `search_policy_generation < policy_generation`, which
 * closes the gate and disables search until the next pass.
 *
 * Reading it at the end would record the newer value and claim the index
 * honoured a policy it had not seen. That is the disclosing direction: §10.8
 * gives this epoch "fail closed" and the whole asymmetry is that search
 * returning nothing is an outage while search returning private sections is a
 * disclosure.
 *
 * ## 🛑 Why there is no window in which both generations answer
 *
 * A query reads `projects.search_generation` once and matches only scope rows
 * carrying that value. Step 5 is a single `UPDATE` of that column, so a query
 * sees either the old number or the new one and never a mixture — and the
 * generation it sees is complete, because step 4 finished before step 5 ran and
 * step 6 has not started. The old rows still exist during step 6 and are
 * unreachable, which is the difference between "deleted promptly" and "cannot
 * be read": §10.8's `0 (in key)` claim for `routing_epoch` rests on the same
 * mechanism, and §8.16.7's "no window" rests on it here.
 *
 * ## 🛑 §9.2's memory budget is a design constraint, not a target
 *
 * "Search indexer peak memory: bounded and declared per driver", measured at
 * "5,000 pages across 3 components". Nothing here accumulates: one document's
 * bytes at a time, {@see self::BATCH_SECTIONS} sections per write, and the
 * batch is dropped before the next is filled. {@see IndexOutcome::$peakBytes}
 * reports what it actually cost, and the exit-criterion test asserts a ceiling
 * — because a budget nobody measures is a budget that has already been
 * exceeded.
 */
final class Indexer
{
    /**
     * 🛑 Sections per write.
     *
     * 500 rows of up to ~20 KB of text is a worst case around 10 MB per batch
     * and a typical case nearer 500 KB, which keeps the peak bounded while
     * still amortising the round trip — the alternative, one insert per
     * section, makes a 40,000-section build 40,000 statements and a pass that
     * takes minutes instead of seconds.
     *
     * The number is here rather than in configuration deliberately: an operator
     * who raised it would be raising §9.2's measured peak, and that is an
     * amendment rather than a setting.
     */
    public const int BATCH_SECTIONS = 500;

    /** Rows deleted per statement by the generation sweep. */
    public const int SWEEP_BATCH = 1_000;

    public function __construct(
        private readonly SearchEngine $engine,
        private readonly SectionExtractor $extractor,
        private readonly StructuredIndex $structured,
        private readonly ManifestReader $manifests,
        private readonly ArtifactStore $store,
        private readonly OrganisationContext $context,
        private readonly SearchBuildIndex $builds,
    ) {}

    /**
     * Index one project, advancing its search generation.
     *
     * @param  bool  $force  re-extract every build even if it is already
     *                       indexed at this extractor version. The operator's
     *                       escape hatch for a corrupted index; it costs a full
     *                       re-read of every artifact and the command says so.
     */
    public function indexProject(Project $project, bool $force = false): IndexOutcome
    {
        /** @var IndexOutcome */
        return $this->context->withinOrganisation(
            $project->organisation_id,
            fn (): IndexOutcome => $this->pass($project, $force),
        );
    }

    private function pass(Project $project, bool $force): IndexOutcome
    {
        /*
         * 🛑 First, before a single version is read. The class note says why
         * the earlier value is the correct one to record.
         */
        $generations = SearchGenerations::forProject($project->id);
        $policyGeneration = $generations->policyGeneration;
        $currentGeneration = $generations->searchGeneration;

        $generation = $currentGeneration + 1;

        /*
         * Both models cast `visibility` to {@see AccessLevel}, so the value is
         * already a lattice member rather than a string. `ScopeLevel` still
         * owns the fail-closed reading of a stored string for the columns that
         * are not cast — the mount's `min_access_snapshot` below is one.
         */
        $projectVisibility = $project->visibility;

        $indexed = 0;
        $reused = 0;
        $skipped = 0;
        $sections = 0;
        $mounts = 0;

        /** @var array<string, true> $touchedBuilds */
        $touchedBuilds = [];

        $versions = $this->versionsToIndex($project);

        foreach ($versions as [$version, $channel]) {
            $manifestId = $version->published_manifest_id;

            if (! is_string($manifestId)) {
                continue;
            }

            $versionVisibility = $version->visibility;

            $componentMounts = $this->componentMountsFor($version);

            /*
             * 🛑 The published manifest's mount table, which is the authority
             * `App\Addons\PublishedBuild` names at length: "the newest `builds`
             * row for this version" ties on `created_at` and is wrong after a
             * rollback, which flips the pointer to an older build and creates
             * no row at all.
             *
             * That class is not called here because it answers a narrower
             * question — §8.7.19's **primary** mount's build — and a composed
             * version has one build per mount, all of which are searchable. So
             * this reads the same table through the same reader, for every
             * mount rather than one.
             */
            foreach ($this->manifests->mounts($manifestId) as $mount) {
                $buildId = $mount['build_id'];

                if (! is_string($buildId) || $buildId === '') {
                    continue;
                }

                $mountPath = $mount['mount_path'];
                $component = $componentMounts[$mountPath] ?? null;

                $minAccess = $component === null
                    ? null
                    : ScopeLevel::fromStored($component['min_access_snapshot']);

                if (! isset($touchedBuilds[$buildId])) {
                    $touchedBuilds[$buildId] = true;

                    $report = $this->indexBuild($buildId, $version, $force);

                    if ($report->reused) {
                        $reused++;
                    } else {
                        $indexed++;
                    }

                    $skipped += $report->skipped;
                    $sections += $report->sections;
                }

                $buildGeneration = $this->builds->liveGenerationFor($buildId);

                if ($buildGeneration === null) {
                    /*
                     * The build produced no live generation — unreadable
                     * artifact, or every page skipped. A scope row pointing at
                     * nothing would be a mount that answers no query, which is
                     * what omitting it also achieves, and omitting it keeps the
                     * invariant that every scope row names a real document set.
                     */
                    continue;
                }

                $this->writeScope(
                    project: $project,
                    version: $version,
                    channel: $channel,
                    generation: $generation,
                    componentMountId: $component['id'] ?? null,
                    buildId: $buildId,
                    buildGeneration: $buildGeneration,
                    scope: ScopeLevel::strongestOf($projectVisibility, $versionVisibility, $minAccess),
                    minAccess: $minAccess,
                );

                $mounts++;
            }
        }

        $liveSections = $this->builds->liveSectionCount(array_keys($touchedBuilds));

        /*
         * 🛑 The swap. One statement, so a query reads one generation or the
         * other and never a mixture.
         *
         * `search_policy_generation` takes the value captured at the top of
         * this method, not `DB::raw('policy_generation')` — a policy write
         * during the pass must leave the gate closed, and reading the column
         * here would silently adopt it.
         */
        Invalidation::advanceSearchGeneration(
            projectId: $project->id,
            generation: $generation,
            policyGeneration: $policyGeneration,
            sections: $liveSections,
        );

        /*
         * 🛑 §8.16.8's filterable attributes, after the swap.
         *
         * The arrays Meilisearch filters on are a **copy** of the scope rows
         * and are refreshed once the rows they copy are live. A driver that
         * needed them to be authoritative would have a window here; neither
         * driver does, because the query's own filter is built from
         * `search_mount_scopes` under both. The copy exists so that §8.16.8's
         * "declared in v1" is true of real values rather than of empty fields —
         * the requirement's reason is that a later addition "forces a mandatory
         * full reindex".
         */
        foreach (array_keys($touchedBuilds) as $buildId) {
            $buildGeneration = $this->builds->liveGenerationFor($buildId);

            if ($buildGeneration !== null) {
                $this->engine->declareFilters(
                    $buildId,
                    $buildGeneration,
                    $this->factsForBuild($buildId, $buildGeneration),
                );
            }
        }

        $this->sweep($project, $generation);

        return new IndexOutcome(
            generation: $generation,
            policyGeneration: $policyGeneration,
            versions: count($versions),
            mounts: $mounts,
            buildsIndexed: $indexed,
            buildsReused: $reused,
            sections: $liveSections,
            skipped: $skipped,
            peakBytes: memory_get_peak_usage(true),
        );
    }

    /**
     * 🛑 §8.16.9's version selection.
     *
     * > "By default only `default`, `stable` and `latest` versions MUST be
     * > indexed; hidden and inactive versions MUST be excluded."
     *
     * The three pointers are read from the project — `default_version_id`,
     * `resolved_stable_version_id` and `resolved_latest_version_id` — because
     * those are what §8.6.4 makes authoritative, and deriving "the newest
     * version" instead is the mistake `PublishedBuild`'s class note records
     * costing Phase 28 a debugging session.
     *
     * 🛑 `active` and `listed` are both checked. `active = false` is inactive;
     * `listed = false` is §8.6's hidden, which is the state a maintainer puts a
     * version in precisely so that it is not advertised — and §8.12.21 lists
     * search among the surfaces that must be generated from the authorised
     * view. A hidden version in the index would be a release announced by its
     * own search results.
     *
     * A version can be two channels at once — `latest` and `stable` very often
     * resolve to the same version, which is `VersionOrder::pinChannels()`'s
     * Phase 28 finding — so the list is deduplicated and the strongest channel
     * name wins.
     *
     * @return list<array{0: ProjectVersion, 1: string}>
     */
    private function versionsToIndex(Project $project): array
    {
        $pointers = [
            'default' => $project->default_version_id,
            'stable' => $project->resolved_stable_version_id,
            'latest' => $project->resolved_latest_version_id,
        ];

        /** @var array<string, array{0: ProjectVersion, 1: string}> $chosen */
        $chosen = [];

        foreach ($pointers as $channel => $versionId) {
            if (! is_string($versionId) || $versionId === '') {
                continue;
            }

            $key = bin2hex($versionId);

            if (isset($chosen[$key])) {
                continue;
            }

            $version = ProjectVersion::query()->whereKey($versionId)->first();

            if (! $version instanceof ProjectVersion) {
                continue;
            }

            if ($version->active !== true || $version->listed !== true || $version->published !== true) {
                continue;
            }

            $chosen[$key] = [$version, $channel];
        }

        return array_values($chosen);
    }

    /**
     * The component mounts of one version, keyed by mount path.
     *
     * Keyed by path because that is what the manifest names — §8.8.3's
     * `mounts_json` carries the path and the build, and the `component_mounts`
     * row is where `min_access_snapshot` lives. A manifest naming a path with
     * no surviving mount row is legitimate (the manifest is immutable, the
     * mount row is not), and the scope then has no `min_access` to narrow by,
     * which is why that parameter is nullable rather than defaulted.
     *
     * @return array<string, array{id: string, min_access_snapshot: string|null}>
     */
    private function componentMountsFor(ProjectVersion $version): array
    {
        $rows = DB::table('component_mounts')
            ->where('project_version_id', $version->id)
            ->get(['id', 'mount_path', 'min_access_snapshot']);

        $mounts = [];

        foreach ($rows as $row) {
            $path = $row->mount_path;

            if (! is_string($path)) {
                continue;
            }

            $mounts[$path] = [
                'id' => is_string($row->id) ? $row->id : '',
                'min_access_snapshot' => is_string($row->min_access_snapshot) ? $row->min_access_snapshot : null,
            ];
        }

        return $mounts;
    }

    /**
     * 🛑 Index one build — or discover it is already indexed and read nothing.
     *
     * This is where §8.16.5's "a reused build is indexed **once**" is decided,
     * and the decision is made **before** {@see BuildFiles} is constructed,
     * because constructing it reads the file manifest out of the artifact
     * store. A check that happened after would still produce the right rows and
     * would have paid for the artifact read, which is the expensive half.
     */
    private function indexBuild(string $buildId, ProjectVersion $version, bool $force): BuildIndexReport
    {
        if (! $force) {
            $live = $this->builds->liveGenerationFor($buildId, SectionExtractor::VERSION);

            if ($live !== null) {
                return new BuildIndexReport(reused: true, generation: $live, sections: 0, skipped: 0);
            }
        }

        $generation = $this->builds->nextGenerationFor($buildId);
        $ranking = $this->rankingFor($buildId);

        $files = new BuildFiles($this->manifests, $this->store, $buildId);
        $language = $version->language !== '' ? $version->language : 'en';

        $this->builds->begin($buildId, $generation, SectionExtractor::VERSION);

        $structured = $this->structured->read($files, $ranking);

        if ($structured !== null) {
            [$from, $sections] = $structured;

            $written = $this->writeInBatches($buildId, $generation, $language, $from, $sections);

            $this->builds->finish(
                buildIdText: $buildId,
                generation: $generation,
                extractedFrom: $from,
                sections: $written,
                documents: $this->distinctPaths($sections),
                skipped: 0,
            );

            return new BuildIndexReport(reused: false, generation: $generation, sections: $written, skipped: 0);
        }

        /*
         * §8.16.3's HTML route, one document at a time. The batch is flushed
         * whenever it fills, so the peak is one document's DOM plus at most
         * {@see self::BATCH_SECTIONS} sections — independent of how many pages
         * the build has, which is §9.2's requirement.
         */
        $batch = [];
        $written = 0;
        $skipped = 0;
        $documents = 0;

        foreach ($files->documents() as $path) {
            if ($ranking->ignores($path)) {
                continue;
            }

            $html = $files->document($path);

            if ($html === null) {
                $skipped++;

                continue;
            }

            $extracted = $this->extractor->extract($path, $html, $ranking);
            unset($html);

            if ($extracted === []) {
                $skipped++;

                continue;
            }

            $documents++;

            foreach ($extracted as $section) {
                $batch[] = $section;

                if (count($batch) >= self::BATCH_SECTIONS) {
                    $written += $this->flush($buildId, $generation, $language, ExtractedFrom::Html, $batch);
                    $batch = [];
                }
            }
        }

        $written += $this->flush($buildId, $generation, $language, ExtractedFrom::Html, $batch);
        $batch = [];

        $this->builds->finish(
            buildIdText: $buildId,
            generation: $generation,
            extractedFrom: ExtractedFrom::Html,
            sections: $written,
            documents: $documents,
            skipped: $skipped,
        );

        return new BuildIndexReport(reused: false, generation: $generation, sections: $written, skipped: $skipped);
    }

    /**
     * §8.16.3's `search.ranking` and `search.ignore`, from the build that
     * declared them.
     *
     * Read from `builds.search_config`, which the pipeline records at build
     * time from the repository's own `.docup.yaml` — the same place and the
     * same way `nav_json` is recorded. Reading the repository here instead
     * would be wrong twice over: §8.21.6's direct uploads have no repository,
     * and a repository's `main` may have moved on since the build.
     */
    private function rankingFor(string $buildId): SearchRanking
    {
        $raw = DB::table('builds')
            ->where('id', Uuid::tryToBytes($buildId) ?? str_repeat("\xff", 16))
            ->value('search_config');

        if (! is_string($raw) || $raw === '') {
            return SearchRanking::none();
        }

        $decoded = json_decode($raw, true, 16);

        return SearchRanking::fromConfig(is_array($decoded) ? $decoded : null);
    }

    /**
     * Write a whole section list in batches.
     *
     * Used by the structured route, which has its sections in hand already —
     * the HTML route batches as it extracts, which is strictly better and is
     * why the two differ. A structured index is already bounded by
     * {@see StructuredIndex::MAX_INDEX_BYTES}, so holding its sections is
     * bounded too.
     *
     * @param  list<Section>  $sections
     */
    private function writeInBatches(
        string $buildId,
        int $generation,
        string $language,
        ExtractedFrom $from,
        array $sections,
    ): int {
        $written = 0;

        foreach (array_chunk($sections, self::BATCH_SECTIONS) as $chunk) {
            $written += $this->flush($buildId, $generation, $language, $from, $chunk);
        }

        return $written;
    }

    /**
     * @param  list<Section>  $batch
     */
    private function flush(
        string $buildId,
        int $generation,
        string $language,
        ExtractedFrom $from,
        array $batch,
    ): int {
        if ($batch === []) {
            return 0;
        }

        $this->engine->writeSections(new SectionBatch(
            buildId: $buildId,
            buildGeneration: $generation,
            language: $language,
            extractedFrom: $from,
            extractorVersion: SectionExtractor::VERSION,
            sections: $batch,
        ));

        return count($batch);
    }

    /**
     * @param  list<Section>  $sections
     */
    private function distinctPaths(array $sections): int
    {
        $paths = [];

        foreach ($sections as $section) {
            $paths[$section->path] = true;
        }

        return count($paths);
    }

    /**
     * One scope row: §8.16.8's filterable set and §8.12.21's visibility scope.
     */
    private function writeScope(
        Project $project,
        ProjectVersion $version,
        string $channel,
        int $generation,
        ?string $componentMountId,
        string $buildId,
        int $buildGeneration,
        AccessLevel $scope,
        ?AccessLevel $minAccess,
    ): void {
        DB::table('search_mount_scopes')->insertOrIgnore([
            'id' => Uuid::v7(),
            'organisation_id' => $project->organisation_id,
            'project_id' => $project->id,
            'project_version_id' => $version->id,
            'component_mount_id' => $componentMountId === '' ? null : $componentMountId,
            'build_id' => Uuid::tryToBytes($buildId) ?? str_repeat("\xff", 16),
            'build_generation' => $buildGeneration,
            'generation' => $generation,
            'scope' => $scope->value,
            'min_access' => $minAccess?->value,
            'language' => $version->language !== '' ? $version->language : 'en',
            'channel' => $channel,
            'created_at' => now(),
        ]);
    }

    /**
     * Every live scope fact for one (build, generation), across all projects.
     *
     * 🛑 **Across all projects**, which is what makes §8.16.8's filter arrays
     * total. A build mounted by two projects has two facts, and writing only
     * the project currently being indexed would erase the other's — so the
     * second project's reindex would make the first project's documents
     * unfilterable by project in Meilisearch.
     *
     * Read across organisations, because a reused build legitimately spans
     * them: §8.7.1 makes a component organisation-owned and mountable by any
     * project version that has a grant, and §8.16.5's "indexed once" is the
     * whole reason that matters.
     *
     * @return list<ScopeFact>
     */
    private function factsForBuild(string $buildId, int $buildGeneration): array
    {
        /** @var list<ScopeFact> */
        return $this->context->acrossAllOrganisations(function () use ($buildId, $buildGeneration): array {
            $rows = DB::table('search_mount_scopes as s')
                ->join('projects as p', 'p.id', '=', 's.project_id')
                ->join('project_versions as v', 'v.id', '=', 's.project_version_id')
                ->whereColumn('s.generation', 'p.search_generation')
                ->where('s.build_id', Uuid::tryToBytes($buildId) ?? str_repeat("\xff", 16))
                ->where('s.build_generation', $buildGeneration)
                ->get([
                    'p.id as project_id',
                    'p.slug as project_slug',
                    'v.id as version_id',
                    'v.slug as version_slug',
                    'v.published_manifest_id as manifest_id',
                    's.scope',
                    's.min_access',
                    's.language',
                    's.channel',
                ]);

            $facts = [];

            foreach ($rows as $row) {
                $facts[] = new ScopeFact(
                    projectId: is_string($row->project_id) ? $row->project_id : '',
                    projectSlug: is_string($row->project_slug) ? $row->project_slug : '',
                    versionId: is_string($row->version_id) ? $row->version_id : '',
                    versionSlug: is_string($row->version_slug) ? $row->version_slug : '',
                    manifestId: is_string($row->manifest_id) ? $row->manifest_id : null,
                    buildId: $buildId,
                    buildGeneration: $buildGeneration,
                    language: is_string($row->language) ? $row->language : 'en',
                    scope: ScopeLevel::fromStored(is_string($row->scope) ? $row->scope : null),
                    minAccess: is_string($row->min_access) ? ScopeLevel::fromStored($row->min_access) : null,
                    channel: is_string($row->channel) ? $row->channel : 'default',
                );
            }

            return $facts;
        });
    }

    /**
     * 🛑 §8.16.11's batched delete, for the superseded generation.
     *
     * > "That table is also **unpartitionable** — MySQL supports neither
     * > FULLTEXT indexes nor FULLTEXT search on partitioned tables — so
     * > retention runs as batched deletes rather than `DROP PARTITION`."
     *
     * The scope rows are small and go in one bounded loop; the **documents**
     * are swept separately by {@see SearchRetention}, on a schedule, because a
     * build's documents outlive any one project's generation — a reused build
     * is still live for the other project that mounts it, and deleting its
     * sections here would break exit criterion 5 the moment two projects
     * reindexed in sequence.
     */
    private function sweep(Project $project, int $generation): void
    {
        do {
            $deleted = DB::table('search_mount_scopes')
                ->where('project_id', $project->id)
                ->where('generation', '<', $generation)
                ->limit(self::SWEEP_BATCH)
                ->delete();
        } while ($deleted >= self::SWEEP_BATCH);
    }
}
