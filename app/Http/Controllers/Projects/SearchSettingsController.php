<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Projects;

use App\Addons\PublishedBuild;
use App\Auth\Capability;
use App\Http\Middleware\ResolveOrganisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Search\EngineLimits;
use App\Search\SearchBuildIndex;
use App\Search\SearchEngine;
use App\Search\SearchGenerations;
use App\Search\SearchRanking;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Inertia\Inertia;
use Inertia\Response;

/**
 * 🛑 §8.16.2's "**in the product UI**, not only the documentation".
 *
 * > §8.16.2: "The documented limits of the default engine MUST be stated **in
 * > the product UI**, not only the documentation: no stemming, no typo
 * > tolerance, a three-character minimum token, 36 default stopwords. 🛑 The
 * > illustration must use a **two**-character term … 'Why can't I find `go`?'
 * > is the real first support question (ADR 0004)."
 *
 * That requirement is easy to satisfy on paper and easy to miss in practice,
 * exactly as §8.12.25's simulator was: a limit stated only in the operator
 * documentation is a limit the person fielding "search is broken" has not read.
 * So this page is where a maintainer looking at their own project's search
 * finds out that `go` returns nothing, with the reason beside it.
 *
 * ## 🛑 Why the numbers come from the engine and not from this file
 *
 * `innodb_ft_min_token_size` is a **server variable**. An operator who raised
 * it to 4 — or lowered it to 2 to make `go` findable — changed the answer to
 * the support question this requirement exists to pre-empt, and a page printing
 * the specification's `3` would then be confidently wrong about the one number
 * the reader came to check. {@see EngineLimits} reads the running
 * server and says so at length.
 *
 * The one figure that is **not** live is ADR 0004's "`api` returns 100,000 hits
 * at 200,000 sections", which no page render can repeat. It is labelled as a
 * measurement rather than presented as a reading, because over-claiming
 * precision is how a number stops being believed.
 *
 * ## A GET, and it changes nothing
 *
 * Everything here is a read: the engine's own limits, the project's generation
 * state and the per-build extraction reports. §8.16's write path is
 * `docup:search-index`, and §8.16.9's version selection is the project's
 * channel pointers rather than a setting on this page — so there is nothing to
 * submit and no audit row to write.
 */
final class SearchSettingsController
{
    /**
     * @param  string  $organisationSlug  the `{organisation}` route parameter,
     *                                    already resolved and authorised by
     *                                    {@see ResolveOrganisation}. Declared
     *                                    because route parameters bind by
     *                                    POSITION.
     */
    public function __invoke(
        Request $request,
        string $organisationSlug,
        Project $project,
        SearchEngine $engine,
        SearchBuildIndex $builds,
        PublishedBuild $published,
    ): Response {
        /*
         * The same capability the policy simulator uses, and for the same
         * reason: this page states how a project's own search behaves, which is
         * maintainer-facing configuration rather than reader-facing content.
         * §12.2 withholds it from `project_reader`.
         */
        abort_unless(
            $request->user()?->can(Capability::ProjectPolicySimulate->value, $project) === true,
            404,
        );

        $generations = SearchGenerations::forProject($project->id);
        $capabilities = $engine->capabilities();

        return Inertia::render('Projects/SearchSettings', [
            'project' => [
                'uuid' => $project->uuid,
                'slug' => $project->slug,
                'name' => $project->name,
            ],

            /* 🛑 §8.16.2's limits and illustrations, read from the engine. */
            'limits' => $engine->limits()->toPayload(),

            /* §8.16.12's published capability matrix, generated from the driver. */
            'capabilities' => $capabilities->rows(),

            'engine' => [
                'driver' => $engine->driver()->value,
                'label' => $engine->driver()->label(),
                'needs_a_service' => $engine->driver()->needsAService(),
                'reachable' => $engine->isReachable(),
                'sections' => $engine->sectionCount(),
                'threshold' => $this->threshold(),
                /*
                 * 🛑 §8.16.1's "recommended above a measured section count,
                 * with a `doctor` warning at the threshold" — surfaced here as
                 * well, because the person who grew the corpus past it is the
                 * maintainer of the project that grew, and they are looking at
                 * this page rather than at `doctor`.
                 */
                'above_threshold' => $engine->sectionCount() > $this->threshold(),
            ],

            /*
             * 🛑 §8.12.21's state, said in words rather than as two numbers.
             *
             * "A project's search MUST be **disabled** while its search
             * generation lags its policy generation" is a condition that
             * persists until a reindex runs and looks like an empty corpus from
             * every other angle. An operator who cannot see it here has no way
             * to find out.
             */
            'generations' => [
                'indexed' => $generations->isIndexed(),
                'search_generation' => $generations->searchGeneration,
                'policy_generation' => $generations->policyGeneration,
                'built_under_policy_generation' => $generations->searchPolicyGeneration,
                'disabled_because_stale' => $generations->lagsPolicy(),
                'indexed_at' => $this->indexedAt($project),
                'section_count' => (int) ($project->search_section_count ?? 0),
            ],

            /* §8.16.9's three channels, and what each one is indexed from. */
            'versions' => $this->versions($project, $builds, $published),

            /*
             * §8.16.3's `search.ranking` and `search.ignore` as the **builds**
             * declared them, including Read the Docs' defaults when a project
             * declared none — because "my 404 page is in the results" and "my
             * 404 page is not in the results" are both questions this answers.
             */
            'ranking' => $this->ranking($project),
        ]);
    }

    /** §8.16.1's measured section count threshold. */
    private function threshold(): int
    {
        $threshold = config('docup.search.meilisearch_recommended_above_sections');

        return is_numeric($threshold) ? (int) $threshold : 200_000;
    }

    private function indexedAt(Project $project): ?string
    {
        $at = $project->search_indexed_at;

        return $at instanceof \DateTimeInterface ? $at->format(DATE_ATOM) : null;
    }

    /**
     * The three channels §8.16.9 indexes, with each one's extraction report.
     *
     * 🛑 The build comes from {@see PublishedBuild}, which is the one answer to
     * "which build does this version publish" — "the newest `builds` row" ties
     * on `created_at` and is wrong after a rollback, which flips the pointer to
     * an older build and creates no row at all. An operator page reporting the
     * wrong build's extraction would send them looking at the wrong artifact.
     *
     * @return list<array{channel: string, slug: string|null, visibility: string|null, indexed: bool, report: array{generation: int, extracted_from: string, sections: int, documents: int, skipped: int, indexed_at: string|null}|null}>
     */
    private function versions(Project $project, SearchBuildIndex $builds, PublishedBuild $published): array
    {
        $pointers = [
            'default' => $project->default_version_id,
            'stable' => $project->resolved_stable_version_id,
            'latest' => $project->resolved_latest_version_id,
        ];

        $rows = [];

        foreach ($pointers as $channel => $versionId) {
            if (! is_string($versionId) || $versionId === '') {
                $rows[] = [
                    'channel' => $channel,
                    'slug' => null,
                    'visibility' => null,
                    'indexed' => false,
                    'report' => null,
                ];

                continue;
            }

            $version = ProjectVersion::query()->whereKey($versionId)->first();

            if (! $version instanceof ProjectVersion) {
                continue;
            }

            /*
             * 🛑 §8.16.9 excludes hidden and inactive versions, so a channel
             * pointing at one is reported as **not indexed** with the version
             * named — which is the question "why is my stable version not
             * searchable" answered before it is asked.
             */
            $eligible = $version->active === true && $version->listed === true && $version->published === true;
            $buildId = $published->idFor($version->published_manifest_id);

            $rows[] = [
                'channel' => $channel,
                'slug' => $version->slug,
                'visibility' => $version->visibility->value,
                'indexed' => $eligible,
                'report' => $eligible && $buildId !== null ? $builds->describe($buildId) : null,
            ];
        }

        return $rows;
    }

    /**
     * The `search:` configuration of the project's indexed builds.
     *
     * @return array{ranking: list<array{pattern: string, rank: int}>, ignore: list<string>, declared: bool}
     */
    private function ranking(Project $project): array
    {
        $raw = DB::table('builds as b')
            ->join('project_versions as v', 'v.id', '=', 'b.project_version_id')
            ->where('v.project_id', $project->id)
            ->whereNotNull('b.search_config')
            ->orderByDesc('b.id')
            ->value('b.search_config');

        if (! is_string($raw) || $raw === '') {
            return [...SearchRanking::none()->describe(), 'declared' => false];
        }

        $decoded = json_decode($raw, true, 16);

        return [
            ...SearchRanking::fromConfig(is_array($decoded) ? $decoded : null)->describe(),
            'declared' => true,
        ];
    }
}
