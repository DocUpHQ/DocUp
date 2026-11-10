<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search\Engines;

use App\Search\AuthorisedScope;
use App\Search\DocumentHit;
use App\Search\EngineCapabilities;
use App\Search\EngineCapability;
use App\Search\EngineLimits;
use App\Search\LiteralTerm;
use App\Search\ParsedQuery;
use App\Search\ScopeFact;
use App\Search\SearchDriver;
use App\Search\SearchEngine;
use App\Search\SearchRefused;
use App\Search\SearchRejection;
use App\Search\SearchTransport;
use App\Search\SectionBatch;

/**
 * §8.16.1's optional engine, "selectable by one environment variable and
 * **recommended above a measured section count**".
 *
 * ## 🛑 §8.16.8: the filterable set is declared in full, in v1
 *
 * > "Every filterable attribute MUST be declared in v1 — project, version,
 * > language, visibility scope, build generation — because changing
 * > Meilisearch's `filterableAttributes` forces a mandatory full reindex, which
 * > makes any later addition a migration event (§15.5)."
 *
 * {@see self::FILTERABLE_ATTRIBUTES} is that list and it is a constant for a
 * reason: adding to it later is a **reindex of every installation**, so the
 * decision belongs in a diff with the requirement's citation beside it rather
 * than in a settings call somebody edits. {@see self::declaredFilterSet()} is
 * asserted against the live index by `MeilisearchContractTest`, and a mismatch
 * is {@see SearchRejection::FilterSetChanged} — surfaced as an upgrade step an
 * operator must run, not a reindex the application starts by itself.
 *
 * ## 🛑 Why the project filter is not how authorisation happens
 *
 * `projects`, `versions` and `scopes` are on each document as multi-valued
 * attributes, maintained from `search_mount_scopes` by
 * {@see self::declareFilters()}. They are there because §8.16.8 requires them
 * declared, and they are genuinely useful for §8.16.10's project and collection
 * filters, which are Phase 30's.
 *
 * They are **not** the authorisation filter. The filter this driver sends is
 * built from {@see AuthorisedScope}'s `(build_id, build_generation)` pairs,
 * which `SearchQuery` derived from `EffectiveAccess` — exactly as the MySQL
 * driver's join does. A copy of an authorisation fact inside a search engine is
 * a copy that can be stale, and §8.12.21 requires these surfaces to be
 * "generated from the **authorised** view", not from a cache of it. So the copy
 * is a convenience and the authority is the database, under both drivers.
 *
 * ## 🛑 Why writes wait for the task
 *
 * Meilisearch indexes asynchronously: a document write returns a `taskUid` and
 * the document is not searchable until the task succeeds. An indexer that did
 * not wait would report a generation live while the engine had not finished
 * reading it — §8.16.7's "no window in which both generations answer" turned
 * into a window in which **neither** does. So {@see self::awaitTask()} blocks,
 * and the indexing path is the only place that pays for it: a reader's search
 * never waits on a task.
 */
final readonly class MeilisearchEngine implements SearchEngine
{
    /**
     * 🛑 §8.16.8's complete filterable set. Changing this forces a full reindex
     * of every installation; see the class note.
     *
     * The five §8.16.8 names, plus `build_id` — which is the attribute the
     * authorisation filter is actually built from, so omitting it would make
     * the requirement's own list insufficient for the requirement's own
     * purpose — and `path`, for the operator tooling that answers "why is this
     * page not findable".
     */
    public const array FILTERABLE_ATTRIBUTES = [
        'build_id',
        'build_generation',
        'language',
        'projects',
        'versions',
        'scopes',
        'path',
    ];

    /**
     * §8.16.3's boosts, as Meilisearch expresses them.
     *
     * The order **is** the weighting: Meilisearch's `attribute` ranking rule
     * prefers a match in an earlier attribute, which is the same intent as the
     * MySQL driver's three FULLTEXT indexes and three weights. Two engines, two
     * mechanisms, one ordering — and the ordering is what the shared contract
     * suite asserts, because a relevance number means nothing across engines.
     */
    public const array SEARCHABLE_ATTRIBUTES = ['title', 'heading_path', 'page_title', 'content'];

    /**
     * 🛑 §8.16.3's per-page rank, placed after `attribute` and before `sort`.
     *
     * Meilisearch's defaults are `words, typo, proximity, attribute, sort,
     * exactness`. Putting `page_rank:desc` after `attribute` means the rank
     * decides between documents that matched equally well in equally important
     * fields — a ranking hint, which is what §8.16.3 asks for. Putting it first
     * would make it a filter: every rank-10 page would outrank every genuine
     * match on a rank-0 one.
     */
    public const array RANKING_RULES = [
        'words',
        'typo',
        'proximity',
        'attribute',
        'page_rank:desc',
        'sort',
        'exactness',
    ];

    /**
     * 🛑 §8.16.12's "implicit AND between terms", which Meilisearch does
     * **not** do by default.
     *
     * Its default is `last`: it drops words from the end of the query until it
     * has results, so `zeta omega` returns documents holding only `zeta`. That
     * is a good default for a typeahead and it is not what §8.16.12 requires of
     * every driver — and the contract suite caught it immediately, asserting
     * one result and getting two.
     *
     * `all` requires every term to be present, which is the default engine's
     * `+term +term` boolean query expressed in Meilisearch's own terms. Sent
     * per search rather than set on the index, so an operator inspecting the
     * index's settings cannot accidentally make the two engines disagree.
     */
    private const string MATCHING_STRATEGY = 'all';

    /** Documents per page when {@see self::declareFilters()} walks a build. */
    private const int FILTER_PAGE = 1_000;

    /** How long {@see self::awaitTask()} waits, in milliseconds. */
    private const int TASK_TIMEOUT_MS = 30_000;

    /** How often it asks, in microseconds. */
    private const int TASK_POLL_US = 50_000;

    public function __construct(private SearchTransport $transport) {}

    public function driver(): SearchDriver
    {
        return SearchDriver::Meilisearch;
    }

    public function capabilities(): EngineCapabilities
    {
        return EngineCapabilities::of(
            SearchDriver::Meilisearch,
            [
                EngineCapability::ImplicitAnd->value => true,
                EngineCapability::ExactPhrase->value => true,
                EngineCapability::ScopeFilters->value => true,
                EngineCapability::TypoTolerance->value => true,
                EngineCapability::Prefix->value => true,
                EngineCapability::Proximity->value => true,
                EngineCapability::FieldWeights->value => true,
                EngineCapability::Highlighting->value => true,
            ],
            [
                EngineCapability::Stemming->value => 'No stemming. Meilisearch tolerates typos, which covers many of the same misses, but '
                    .'`deploying` still does not match `deploy` — the same limit the default engine has, '
                    .'reached by a different route.',
                /*
                 * 🛑 The two capabilities this engine HAS and DocUp does not
                 * offer are stated here rather than silently enjoyed.
                 * §8.16.12's minimum syntax is the whole syntax: a prefix or a
                 * fuzzy operator DocUp accepted here would be an operator it
                 * ignores on the default engine, and "the identical suite
                 * passes on both engines" would stop being true. The engine's
                 * own typo tolerance applies to every query automatically,
                 * which is a better result for the same reader with no syntax
                 * at all.
                 */
                EngineCapability::Prefix->value => 'Applied by the engine to the last word of a query, as Meilisearch does by default. There is '
                    .'no prefix OPERATOR, because §8.16.12 fixes one syntax for every driver and the default '
                    .'engine has none.',
            ],
        );
    }

    public function limits(): EngineLimits
    {
        /*
         * Meilisearch has no minimum token size and no stopword list unless an
         * operator configures one, so the numbers that matter for §8.16.2 are
         * genuinely different rather than unknown: a two-character term is
         * searchable, and `go` finds `go`. Reported as 1 and 0 rather than
         * omitted, because the UI panel's job is to state what is true of this
         * installation and "no minimum" is a fact worth seeing.
         */
        return new EngineLimits(
            driver: SearchDriver::Meilisearch,
            minTokenSize: 1,
            maxTokenSize: 0,
            stopwordCount: 0,
            stemming: false,
            typoTolerance: true,
        );
    }

    public function isReachable(): bool
    {
        if (! $this->transport->isConfigured()) {
            return false;
        }

        try {
            $response = $this->transport->send('GET', '/health');
        } catch (SearchRefused) {
            return false;
        }

        return $response['status'] === 200;
    }

    /**
     * 🛑 Declare the index's settings, idempotently.
     *
     * Called by `docup:search-index` before a pass and by `doctor`. It is not
     * called from a request path: a settings write on Meilisearch triggers a
     * reindex of the whole index, and doing that from a reader's search would
     * be a denial of service with a correct-looking 200.
     *
     * @throws SearchRefused when the live filterable set differs from
     *                       {@see self::FILTERABLE_ATTRIBUTES} and the index
     *                       already holds documents — §8.16.8's "migration
     *                       event", surfaced rather than performed
     */
    public function declareSettings(bool $allowReindex = false): void
    {
        $index = $this->index();

        /*
         * 🛑 Created only when absent, and **awaited** when created.
         *
         * Two defects were found here within a minute of each other, and both
         * were silent:
         *
         * 1. The first version did not await the creation task, so the settings
         *    `PATCH` below raced it and lost on a cold engine. The settings
         *    task then failed, `filterableAttributes` stayed empty, and every
         *    search got a 400 saying `build_id` is not filterable — which
         *    {@see self::search0()} returned as a body with no `hits` key, i.e.
         *    as **zero results**. A misconfigured index was indistinguishable
         *    from an empty corpus, for every query. `search0()` now refuses a
         *    non-200 for exactly that reason.
         * 2. Awaiting it then made the **second** run fail, because creating an
         *    index that exists is a task that fails with
         *    `index_already_exists`. Unconditional creation is wrong on every
         *    run after the first, which is every run in production.
         *
         * So the existence check comes first. It is also cheaper: the common
         * case is one `GET` rather than a create and a wait.
         */
        if ($this->transport->send('GET', '/indexes/'.$index)['status'] !== 200) {
            $created = $this->transport->send('POST', '/indexes', ['uid' => $index, 'primaryKey' => 'id']);

            $this->awaitTask($created['body']);
        }

        $live = $this->declaredFilterSet();

        if ($live !== null && $live !== self::FILTERABLE_ATTRIBUTES && ! $allowReindex && $this->sectionCount() > 0) {
            throw new SearchRefused(SearchRejection::FilterSetChanged, [
                'live' => count($live),
                'expected' => count(self::FILTERABLE_ATTRIBUTES),
            ]);
        }

        $response = $this->transport->send('PATCH', '/indexes/'.$index.'/settings', [
            'filterableAttributes' => self::FILTERABLE_ATTRIBUTES,
            'searchableAttributes' => self::SEARCHABLE_ATTRIBUTES,
            'rankingRules' => self::RANKING_RULES,
            'sortableAttributes' => ['page_rank', 'position'],
        ]);

        $this->awaitTask($response['body']);
    }

    /**
     * The filterable attributes the live index declares, sorted as this class
     * writes them, or null when the index does not exist.
     *
     * @return list<string>|null
     */
    public function declaredFilterSet(): ?array
    {
        try {
            $response = $this->transport->send('GET', '/indexes/'.$this->index().'/settings/filterable-attributes');
        } catch (SearchRefused) {
            return null;
        }

        if ($response['status'] !== 200) {
            return null;
        }

        $attributes = [];

        foreach ($response['body'] as $attribute) {
            if (is_string($attribute)) {
                $attributes[] = $attribute;
            }
        }

        sort($attributes);
        $expected = self::FILTERABLE_ATTRIBUTES;
        sort($expected);

        /*
         * Returned in this class's own declaration order when the sets match,
         * so a caller comparing against the constant does not also have to
         * think about ordering — Meilisearch returns them in its own.
         */
        return $attributes === $expected ? self::FILTERABLE_ATTRIBUTES : $attributes;
    }

    /**
     * 🛑 The extractor version is **not** part of this answer, and it cannot be.
     *
     * §8.16.8's filterable set is frozen in v1, so `extractor_version` is not
     * filterable and adding it would be the migration event the requirement
     * exists to prevent. That is not a gap: the question "which extractor wrote
     * this generation" is answered by `search_build_index`, the
     * driver-independent bookkeeping the indexer actually consults, and asking
     * the engine would have been a network round trip per build during a
     * 5,000-page pass.
     *
     * So this method answers the narrower question the seam can answer on both
     * drivers — does this generation hold documents at all — and the parameter
     * is accepted and ignored rather than removed, because the default driver
     * can answer the fuller question and the seam should not be narrowed to the
     * weaker engine.
     */
    public function hasSections(string $buildId, int $buildGeneration, int $extractorVersion): bool
    {
        $response = $this->search0(filter: $this->buildFilter([[$buildId, $buildGeneration]]));

        return is_numeric($response['estimatedTotalHits'] ?? null)
            && (int) $response['estimatedTotalHits'] > 0;
    }

    public function writeSections(SectionBatch $batch): void
    {
        if ($batch->isEmpty()) {
            return;
        }

        $documents = [];

        foreach ($batch->sections as $section) {
            $documents[] = [
                /*
                 * 🛑 A **deterministic** primary key, so a re-run of a pass
                 * that died halfway replaces rather than duplicates. Meilisearch
                 * has no unique index to lean on — the primary key is the only
                 * identity — so the key has to be derived from the same four
                 * values `search_documents_section_unique` is built on.
                 *
                 * A hash because the key may hold only `[a-zA-Z0-9_-]`, and a
                 * path contains neither of the two characters a naive join
                 * would need. The input is joined with a NUL, which cannot
                 * occur in any of the parts, so two different sections cannot
                 * produce one key by concatenation.
                 */
                'id' => $this->documentId($batch->buildId, $batch->buildGeneration, $section->path, $section->anchor),
                'build_id' => $batch->buildId,
                'build_generation' => $batch->buildGeneration,
                'language' => $batch->language,
                'path' => $section->path,
                'anchor' => $section->anchor,
                'title' => $section->title,
                'heading_path' => $section->headingPath,
                'page_title' => $section->pageTitle,
                'content' => $section->content,
                'page_rank' => $section->rank,
                'position' => $section->position,
                'extracted_from' => $batch->extractedFrom->value,
                'extractor_version' => $batch->extractorVersion,

                /*
                 * 🛑 Empty on write, filled by `declareFilters()` after the
                 * swap. Writing the indexing project's own ids here would make
                 * the arrays depend on which project indexed the build first,
                 * and a reused build's second project would never appear.
                 */
                'projects' => [],
                'versions' => [],
                'scopes' => [],
            ];
        }

        /*
         * 🛑 `POST` is **add-or-replace** and `PUT` is **add-or-update**, and
         * this is the write that wants replace.
         *
         * Meilisearch's two verbs are the opposite way round from most HTTP
         * APIs, and getting them backwards cost an hour. The first version used
         * `PUT` here and `POST` in {@see self::declareFilters()} — so the full
         * documents were merged in and then **replaced** by the filter-only
         * payload, leaving every document with four fields: `id`, `projects`,
         * `versions`, `scopes`. No title, no content, no `build_id`.
         *
         * The symptom was every contract test returning nothing while the
         * index reported 96 documents and the correct `filterableAttributes`.
         * `GET /indexes/{uid}/stats`'s `fieldDistribution` is what showed it.
         * Recorded in §14.3's trap list.
         */
        $response = $this->transport->send('POST', '/indexes/'.$this->index().'/documents', $documents);

        $this->awaitTask($response['body']);
    }

    /**
     * 🛑 §8.16.8's filter arrays, refreshed from the complete fact set.
     *
     * `PUT`, which is Meilisearch's **add-or-update**: it merges by primary key
     * and leaves the fields it does not mention alone, so the section text is
     * neither re-sent nor lost. {@see self::writeSections()} records what
     * happened when these two verbs were the other way round.
     *
     * @param  list<ScopeFact>  $facts
     */
    public function declareFilters(string $buildId, int $buildGeneration, array $facts): void
    {
        $projects = [];
        $versions = [];
        $scopes = [];

        foreach ($facts as $fact) {
            $projects[$fact->projectSlug] = true;
            $versions[$fact->versionSlug] = true;
            $scopes[$fact->scope->value] = true;
        }

        $filter = $this->buildFilter([[$buildId, $buildGeneration]]);
        $offset = 0;

        /*
         * 🛑 Paged. A build has as many documents as it has sections — tens of
         * thousands on a real Sphinx site — and a single capped read would
         * update the first page and leave the rest with empty filter arrays.
         * The symptom would be a `project:` filter that worked for the first
         * few hundred sections of every build, which is the kind of bug that
         * gets reported as "search is inconsistent".
         */
        while (true) {
            $hits = $this->search0(filter: $filter, limit: self::FILTER_PAGE, offset: $offset);
            $page = $hits['hits'] ?? null;

            if (! is_array($page) || $page === []) {
                return;
            }

            $updates = [];

            foreach ($page as $hit) {
                if (! is_array($hit) || ! is_string($hit['id'] ?? null)) {
                    continue;
                }

                $updates[] = [
                    'id' => $hit['id'],
                    'projects' => array_keys($projects),
                    'versions' => array_keys($versions),
                    'scopes' => array_keys($scopes),
                ];
            }

            if ($updates !== []) {
                $response = $this->transport->send('PUT', '/indexes/'.$this->index().'/documents', $updates);
                $this->awaitTask($response['body']);
            }

            if (count($page) < self::FILTER_PAGE) {
                return;
            }

            $offset += self::FILTER_PAGE;
        }
    }

    public function forgetSections(string $buildId, int $buildGeneration): int
    {
        $before = $this->search0(filter: $this->buildFilter([[$buildId, $buildGeneration]]));
        $estimate = $before['estimatedTotalHits'] ?? null;
        $count = is_numeric($estimate) ? (int) $estimate : 0;

        if ($count === 0) {
            return 0;
        }

        $response = $this->transport->send('POST', '/indexes/'.$this->index().'/documents/delete', [
            'filter' => $this->buildFilter([[$buildId, $buildGeneration]]),
        ]);

        $this->awaitTask($response['body']);

        return $count;
    }

    /**
     * @return list<DocumentHit>
     */
    public function search(ParsedQuery $query, AuthorisedScope $scope, int $limit): array
    {
        /* The same guard, the same reason as the default driver. */
        if ($scope->isEmpty() || $query->isEmpty()) {
            return [];
        }

        $keys = $scope->documentKeys();

        if ($keys === []) {
            return [];
        }

        try {
            $response = $this->search0(
                q: $this->queryString($query),
                filter: $this->buildFilter($keys),
                limit: max(1, $limit),
            );
        } catch (SearchRefused) {
            /*
             * 🛑 An unreachable engine is an empty result set on the reader's
             * path, never an exception. §8.16.1 makes the default engine
             * serviceless so that the optional one's outage is survivable, and
             * that promise is only kept here: a 500 on every documentation page
             * carrying a search box would be a worse outage than search being
             * unavailable. `doctor` and `SearchQuery` are where the reason is
             * reported.
             */
            return [];
        }

        $hits = [];
        $page = $response['hits'] ?? null;

        if (! is_array($page)) {
            return [];
        }

        foreach ($page as $hit) {
            if (! is_array($hit)) {
                continue;
            }

            $buildId = $hit['build_id'] ?? null;
            $path = $hit['path'] ?? null;

            if (! is_string($buildId) || ! is_string($path)) {
                continue;
            }

            $hits[] = new DocumentHit(
                buildId: $buildId,
                buildGeneration: is_numeric($hit['build_generation'] ?? null) ? (int) $hit['build_generation'] : 0,
                path: $path,
                anchor: is_string($hit['anchor'] ?? null) ? $hit['anchor'] : null,
                title: is_string($hit['title'] ?? null) ? $hit['title'] : '',
                headingPath: is_string($hit['heading_path'] ?? null) ? $hit['heading_path'] : '',
                pageTitle: is_string($hit['page_title'] ?? null) ? $hit['page_title'] : '',
                content: is_string($hit['content'] ?? null) ? $hit['content'] : '',
                rank: is_numeric($hit['page_rank'] ?? null) ? (int) $hit['page_rank'] : 0,

                /*
                 * 🛑 Meilisearch returns no score by default and DocUp does not
                 * ask for one. Its ranking is an **ordering** produced by the
                 * ranking rules, not a number — so the position in the list is
                 * the information, and inventing a score from the index would
                 * invite a comparison across engines that means nothing.
                 * `DocumentHit::$score` says the same thing from the other side.
                 */
                score: 0.0,
            );
        }

        return $hits;
    }

    public function sectionCount(): int
    {
        try {
            $response = $this->transport->send('GET', '/indexes/'.$this->index().'/stats');
        } catch (SearchRefused) {
            return 0;
        }

        $count = $response['body']['numberOfDocuments'] ?? null;

        return is_numeric($count) ? (int) $count : 0;
    }

    /**
     * 🛑 §8.16.12's syntax, as a Meilisearch query string.
     *
     * Terms are space-separated and phrases keep their double quotes, which is
     * §8.16.12's exact phrase. The implicit AND is **not** free here: see
     * {@see self::MATCHING_STRATEGY}.
     *
     * 🛑 The per-term reduction is {@see LiteralTerm}'s, shared with the
     * default driver, so a reader who types `~term` gets the same answer on
     * both engines. That class records the divergence that made it necessary.
     */
    private function queryString(ParsedQuery $query): string
    {
        $parts = [];

        foreach ($query->terms as $term) {
            foreach (LiteralTerm::wordsOf($term) as $word) {
                $parts[] = $word;
            }
        }

        foreach ($query->phrases as $phrase) {
            $clean = LiteralTerm::of($phrase);

            if ($clean !== '') {
                $parts[] = '"'.$clean.'"';
            }
        }

        return implode(' ', $parts);
    }

    /**
     * 🛑 The authorisation filter, built **only** from the authorised scope.
     *
     * Each build id is a UUID and each generation an integer, both of them
     * server-derived — so there is no value here a reader can influence and
     * nothing to escape. The assertion is structural: the only parameter is a
     * list of pairs that came out of {@see AuthorisedScope}, and
     * `SearchArchitectureTest` asserts no request input reaches this method.
     *
     * The UUID is still matched against a strict shape before it is
     * interpolated, because defence in depth costs one regex here and the
     * alternative is a filter expression assembled from a database column.
     *
     * @param  list<array{0: string, 1: int}>  $keys
     */
    private function buildFilter(array $keys): string
    {
        $clauses = [];

        foreach ($keys as [$buildId, $buildGeneration]) {
            if (preg_match('/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/', $buildId) !== 1) {
                continue;
            }

            $clauses[] = '(build_id = "'.$buildId.'" AND build_generation = '.(int) $buildGeneration.')';
        }

        if ($clauses === []) {
            /*
             * 🛑 A filter that matches nothing, never an absent filter. An
             * empty string here would be an unfiltered search over the whole
             * index — §8.16.6's failure in one line — so the degenerate case
             * is spelled out rather than left to a falsy check upstream.
             */
            return 'build_id = "00000000-0000-0000-0000-000000000000" AND build_generation = -1';
        }

        return implode(' OR ', $clauses);
    }

    /**
     * One raw search against the configured index.
     *
     * @return array<array-key, mixed>
     */
    private function search0(string $q = '', string $filter = '', int $limit = 1, int $offset = 0): array
    {
        $response = $this->transport->send('POST', '/indexes/'.$this->index().'/search', [
            'q' => $q,
            'filter' => $filter,
            'limit' => $limit,
            'offset' => $offset,
            'matchingStrategy' => self::MATCHING_STRATEGY,
            'attributesToRetrieve' => [
                'id', 'build_id', 'build_generation', 'path', 'anchor',
                'title', 'heading_path', 'page_title', 'content', 'page_rank', 'position',
            ],
        ]);

        /*
         * 🛑 A non-200 is a **refusal**, never an empty result set.
         *
         * Meilisearch answers 400 with a JSON body and no `hits` key when a
         * filter names an attribute that is not filterable — which is exactly
         * what an index whose §8.16.8 settings were never applied does to every
         * search. Reading that body as zero results made a broken index
         * indistinguishable from an empty corpus, for every query, silently.
         *
         * `SearchQuery` turns this into `SearchState::EngineUnavailable`, which
         * an operator can see and a reader experiences as search being
         * unavailable rather than as the documentation having nothing in it.
         */
        if ($response['status'] !== 200) {
            throw new SearchRefused(SearchRejection::EngineRefused, [
                'status' => $response['status'],
            ]);
        }

        return $response['body'];
    }

    /**
     * 🛑 Wait for a write task, because Meilisearch indexes asynchronously.
     *
     * The class note gives the reason: a generation reported live before the
     * engine finished reading it is §8.16.7's window with neither generation
     * answering instead of both.
     *
     * A timeout **throws**, so the indexer records the build as unfinished
     * rather than marking a generation live on an engine that never caught up.
     *
     * @param  array<array-key, mixed>  $body  the enqueue response
     */
    private function awaitTask(array $body): void
    {
        $taskUid = $body['taskUid'] ?? ($body['uid'] ?? null);

        if (! is_numeric($taskUid)) {
            return;
        }

        $deadline = (int) (microtime(true) * 1000) + self::TASK_TIMEOUT_MS;

        while ((int) (microtime(true) * 1000) < $deadline) {
            $response = $this->transport->send('GET', '/tasks/'.(int) $taskUid);
            $status = $response['body']['status'] ?? null;

            if ($status === 'succeeded') {
                return;
            }

            if ($status === 'failed' || $status === 'canceled') {
                throw new SearchRefused(SearchRejection::EngineRefused, ['task' => (int) $taskUid]);
            }

            usleep(self::TASK_POLL_US);
        }

        throw new SearchRefused(SearchRejection::EngineUnreachable, ['task' => (int) $taskUid]);
    }

    /** Deterministic primary key for one section. */
    private function documentId(string $buildId, int $generation, string $path, ?string $anchor): string
    {
        return substr(hash('sha256', implode("\0", [$buildId, (string) $generation, $path, $anchor ?? ''])), 0, 40);
    }

    /**
     * The index name.
     *
     * 🛑 Narrowed to the characters Meilisearch permits in a uid, so a
     * misconfigured value cannot carry a path segment into every URL this class
     * builds. The transport refuses a non-origin-relative path as well; this is
     * the layer that holds if somebody later writes a URL by hand.
     */
    private function index(): string
    {
        $configured = config('docup.search.meilisearch.index');
        $index = is_string($configured) ? $configured : '';
        $index = (string) preg_replace('/[^A-Za-z0-9_-]+/', '', $index);

        return $index === '' ? 'docup_search' : substr($index, 0, 64);
    }
}
