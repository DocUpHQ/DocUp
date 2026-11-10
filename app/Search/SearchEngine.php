<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * 🛑 §8.16.1's seam. One interface, two drivers, and the boundary that makes
 * "switching to Meilisearch passes the identical suite" a claim worth testing.
 *
 * > §8.16.1: "Search MUST sit behind one `SearchEngine` seam with 🛑 **MySQL
 * > InnoDB FULLTEXT as the shipped default** (no additional service —
 * > requirement §8.1.1) and **Meilisearch** selectable by one environment
 * > variable."
 *
 * ## 🛑 What is deliberately NOT behind this seam
 *
 * **Authorisation.** A driver receives an {@see AuthorisedScope} that has
 * already been decided by `EffectiveAccess`, and it may only ever narrow it
 * further. There is no method here that takes a filter expression, a reader
 * identity, a project slug or anything else a request supplied, and
 * `SearchArchitectureTest` asserts no driver reads a request, a session or the
 * database's authorisation tables. §8.16.6 requires visibility filtering to be
 * "server-side only"; the cheapest way to guarantee that across two engines is
 * for neither engine to be able to do it.
 *
 * **URL computation.** §8.16.5 computes result URLs at query time from the
 * manifest's mount table, so a driver returns {@see DocumentHit} objects keyed
 * to a build and never a URL. A driver that knew the URL would have to be told
 * which project asked, which is the authorisation fact above wearing a hat.
 *
 * **The scope table.** `search_mount_scopes` is a database table under both
 * drivers, because it holds authorisation facts derived from the database and
 * §8.12.21 makes those "generated from the authorised view". Meilisearch holds
 * a **copy** of them as filterable attributes — declared in full in v1 per
 * §8.16.8 — but the copy is never the authority.
 *
 * ## The ordering contract both drivers owe
 *
 * Relevance numbers are not comparable across engines (see
 * {@see DocumentHit::$score}), so what the shared suite asserts is **order**:
 * a term in a section's own heading outranks the same term in its body, a
 * higher §8.16.3 page rank outranks a lower one at equal match quality, and
 * `position` breaks a tie so two runs of the same query cannot differ.
 */
interface SearchEngine
{
    /** Which driver this is. */
    public function driver(): SearchDriver;

    /** §8.16.12's capability matrix row for this driver. */
    public function capabilities(): EngineCapabilities;

    /** 🛑 §8.16.2's limits, read live where the engine can report them. */
    public function limits(): EngineLimits;

    /**
     * Whether this engine can be reached at all.
     *
     * 🛑 Asked by `doctor` and by the query path, and it is the reason a
     * Meilisearch outage is an **empty result set with a stated reason** rather
     * than a 500 on every documentation page that has a search box. §8.16.1
     * makes the default engine serviceless precisely so that the failure mode
     * of the optional one is recoverable.
     */
    public function isReachable(): bool;

    /**
     * 🛑 §8.16.5's "indexed **once**": does this (build, generation) already
     * hold documents from this extractor?
     *
     * The indexer asks before reading a single artifact byte. A build mounted
     * by three projects is extracted on the first project's pass and skipped on
     * the other two — which is the whole of exit criterion 5's "indexed once",
     * and the only part of it that is measurable: the proof is that the
     * extractor was not called, not that the row count looks right.
     *
     * @param  string  $buildId  canonical UUID text
     */
    public function hasSections(string $buildId, int $buildGeneration, int $extractorVersion): bool;

    /**
     * Write one build's sections at one generation.
     *
     * 🛑 Idempotent and **batched**. §9.2 budgets "search indexer peak memory:
     * bounded and declared per driver" at "5,000 pages across 3 components", so
     * a driver may not accumulate: it is handed a batch, it writes it, and the
     * caller holds no reference to it afterwards. A driver that buffered until
     * the end would pass every functional test and fail the one budget this
     * phase is measured against.
     *
     * @throws SearchRefused when the engine cannot accept the batch
     */
    public function writeSections(SectionBatch $batch): void;

    /**
     * 🛑 §8.16.8's filterable attributes, for the engines that need them on the
     * document.
     *
     * > "Every filterable attribute MUST be declared in v1 — project, version,
     * > language, visibility scope, build generation — because changing
     * > Meilisearch's `filterableAttributes` forces a mandatory full reindex,
     * > which makes any later addition a migration event (§15.5)."
     *
     * Called with the **complete** set of scope facts for one (build,
     * generation) — every project that mounts it, not just the one being
     * indexed — because a Meilisearch document's filter arrays must be total or
     * the second project's reindex would erase the first's.
     *
     * A no-op on the default driver, where the facts live in
     * `search_mount_scopes` and the join is the truth. Stated on the interface
     * rather than left to each driver to guess, so that "declared in v1" is a
     * property of the seam.
     *
     * @param  list<ScopeFact>  $facts
     */
    public function declareFilters(string $buildId, int $buildGeneration, array $facts): void;

    /**
     * Delete every document for one (build, generation).
     *
     * 🛑 §8.16.7's "delete-by-filter", and on the default driver it is
     * **batched**: §8.16.11 makes `search_documents` unpartitionable, so there
     * is no `DROP PARTITION` and an unbatched delete of a 200,000-row
     * generation is a long transaction on a §10.9 hot table.
     *
     * @return int documents removed
     */
    public function forgetSections(string $buildId, int $buildGeneration): int;

    /**
     * The query.
     *
     * 🛑 The scope is the filter. A driver MUST return nothing for an empty
     * scope and MUST NOT widen the set for any reason — §8.16.6's "server-side
     * only" is this parameter.
     *
     * @param  int  $limit  the result cap. 🛑 §8.16.6: the filtered cost "scales
     *                      with **match-set size, not result limit**", so a
     *                      smaller limit does not make a broad query cheap and
     *                      no driver may imply otherwise by treating this as a
     *                      performance control.
     * @return list<DocumentHit> most relevant first
     */
    public function search(ParsedQuery $query, AuthorisedScope $scope, int $limit): array;

    /**
     * 🛑 §8.16.1's "measured section count", for the Meilisearch threshold and
     * `doctor`'s warning.
     *
     * The engine's own count of live documents, which is the number the
     * threshold is defined against — not the sum of per-project counters, which
     * double-count a reused build by design.
     */
    public function sectionCount(): int;
}
