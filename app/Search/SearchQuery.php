<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

use App\Access\ReaderContext;
use App\Serving\SnapshotMount;

/**
 * 🛑 The one entry point for a reader's search. Parse, authorise, match,
 * compute URLs.
 *
 * > §8.16.6: "Search MUST be proxied server-side; no browser-readable search
 * > token of any kind MUST be issued."
 *
 * This class is that proxy. Nothing else in DocUp may call a
 * {@see SearchEngine} on a reader's behalf, and `SearchArchitectureTest`
 * asserts it: an engine reached from anywhere else would be an engine reached
 * without {@see SearchScopes} having run, and §8.16.6's "server-side only"
 * would be a convention rather than a structure.
 *
 * ## The order of operations is the security property
 *
 * 1. **Parse.** {@see QueryParser} reduces the reader's string to terms,
 *    phrases and scope *requests*. No filter expression exists at any point.
 * 2. **Authorise.** {@see SearchScopes} asks `EffectiveAccess`, per version,
 *    with `AccessSurface::Search` — which is where §8.12.21's generation gate
 *    fires. The result is a set of build keys.
 * 3. **Match.** The engine receives the parsed query and that set, and can
 *    only narrow it.
 * 4. **Compute.** {@see SearchUrls} turns build-relative hits into URLs from
 *    the manifest (§8.16.5).
 *
 * Step 2 cannot be skipped, because step 3 takes its output as a parameter and
 * both drivers return nothing for an empty one. That is the whole design: the
 * filter is not something a driver remembers to apply, it is the only thing a
 * driver is given.
 *
 * ## 🛑 What this phase deliberately does not do
 *
 * There is no controller, no route and no public API. §17 gives Phase 30
 * "search-as-you-type wired to the addons payload, the public search API,
 * cross-project search within a collection (§8.16.10), result highlighting,
 * the penalty box" — so `search.enabled` stays `false` in
 * `App\Addons\AddonsPayload::search()` and this class is reached from the
 * artisan command, the operator UI and the tests.
 *
 * The decision is recorded in the build log rather than left implicit: Phase 28
 * pointed its notes at this phase for the flag, and §17 puts the wiring in
 * Phase 30. Shipping the endpoint here would also mean shipping it without
 * §8.16.10's rate limiter, which §9.3.5 names among the paths that must have
 * one. So the index and the query path are complete and the reader-facing
 * surface is Phase 30's, with nothing half-built in between.
 */
final readonly class SearchQuery
{
    /**
     * §9.2's search budget is p95 < 200 ms at 500k sections, and §8.16.6's
     * measured cost "scales with **match-set size, not result limit**" — so
     * this cap is about the response and the reader, not about the query's
     * cost. Ten is what §8.15.8's combobox shows.
     */
    public const int DEFAULT_LIMIT = 10;

    /** The most results one call will return. */
    public const int MAX_LIMIT = 50;

    public function __construct(
        private SearchEngine $engine,
        private QueryParser $parser,
        private SearchScopes $scopes,
        private SearchUrls $urls,
    ) {}

    /**
     * Search within one resolved project.
     *
     * @param  string  $queryString  exactly as the reader typed it
     * @param  SnapshotMount  $mount  the resolved mount — §12.3's per-host
     *                                `mount_exposure` arrives with it, which is
     *                                why a search is answered against a mount
     *                                and not against a project
     * @param  ReaderContext|null  $reader  null is anonymous
     */
    public function forMount(
        string $queryString,
        SnapshotMount $mount,
        ?ReaderContext $reader = null,
        int $limit = self::DEFAULT_LIMIT,
    ): SearchOutcome {
        $limit = max(1, min(self::MAX_LIMIT, $limit));
        $query = $this->parser->parse($queryString);

        if ($query->isEmpty()) {
            /*
             * 🛑 Before authorisation, and deliberately: a query with nothing
             * to match cannot return anything whoever asked, so answering it
             * here spends no decision and writes no §20.3 record. An empty
             * query from an anonymous reader is not an access event.
             */
            return new SearchOutcome([], SearchState::EmptyQuery, $this->engine->driver());
        }

        $scope = $this->scopes->forMount($mount, $reader, $query->scopes);

        if ($scope->gateClosed) {
            return new SearchOutcome([], SearchState::GenerationStale, $this->engine->driver());
        }

        if ($scope->isEmpty()) {
            /*
             * Not authorised, or never indexed. Distinguished for the operator
             * by {@see SearchGenerations::isIndexed()}, which is one read the
             * denying path can afford because it only runs when there is
             * nothing to search anyway.
             */
            $state = SearchGenerations::forProject($mount->project->id)->isIndexed()
                ? SearchState::NotAuthorised
                : SearchState::NotIndexed;

            return new SearchOutcome([], $state, $this->engine->driver());
        }

        if (! $this->engine->isReachable()) {
            return new SearchOutcome([], SearchState::EngineUnavailable, $this->engine->driver());
        }

        /*
         * 🛑 A refusal from the engine is an empty result set, never an
         * exception on a reader's path. `SearchRefused`'s own docblock states
         * the reason: §8.16.1 makes the default engine serviceless so that the
         * optional one's outage is survivable, and that promise is kept here or
         * nowhere.
         */
        try {
            $hits = $this->engine->search($query, $scope, $limit);
        } catch (SearchRefused) {
            return new SearchOutcome([], SearchState::EngineUnavailable, $this->engine->driver());
        }

        return new SearchOutcome(
            $this->urls->resultsFor($hits, $scope, $limit),
            SearchState::Answered,
            $this->engine->driver(),
        );
    }
}
