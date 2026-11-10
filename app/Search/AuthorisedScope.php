<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * 🛑 What a reader may search, decided before any engine is asked.
 *
 * > §8.16.6: "Visibility filters MUST be applied **server-side only**, derived
 * > from project authorisation, version visibility and each matched mount's
 * > `min_access`."
 *
 * An engine receives one of these and a {@see ParsedQuery} and nothing else.
 * The engine's filter is built from **this** object's build keys — never from
 * the query — so there is no expression a reader can write that reaches a
 * driver, and no driver that can be asked for a document outside the set.
 *
 * ## 🛑 Empty means empty, and that is a complete answer
 *
 * An empty scope is the result for an anonymous reader on a private project, a
 * project whose search generation lags its policy generation (§8.12.21), a
 * project that has never been indexed, and a `project:` request naming
 * something the reader cannot read. All four produce no results and none of
 * them is distinguishable from the others by the reader — which is the point:
 * §8.12.23's reasoning for 404-over-403 applies to a result set as much as to a
 * response status, because "zero results" and "zero results you may see" must
 * look identical or the empty set becomes an oracle.
 *
 * {@see self::isEmpty()} is therefore checked by every driver before it builds
 * a query, and the architecture test asserts each one does. A driver that built
 * an unfiltered `MATCH` for an empty scope would return the whole installation.
 */
final readonly class AuthorisedScope
{
    /**
     * @param  list<ScopeFact>  $facts  the mount contexts this reader may search
     * @param  bool  $gateClosed  🛑 §8.12.21: true when at least one project in
     *                            the requested set had search **disabled**
     *                            because its search generation lagged its
     *                            policy generation. Carried so the surface can
     *                            say "search is unavailable" rather than
     *                            "nothing matched" — the two are different
     *                            facts and conflating them is how a disabled
     *                            index gets reported as an empty corpus for a
     *                            week.
     */
    public function __construct(
        public array $facts,
        public bool $gateClosed = false,
    ) {}

    /** Nothing to search. */
    public function isEmpty(): bool
    {
        return $this->facts === [];
    }

    /** An empty scope with the gate flag set, for §8.12.21's refusal. */
    public static function gated(): self
    {
        return new self(facts: [], gateClosed: true);
    }

    /** An empty scope, for every other reason. */
    public static function nothing(): self
    {
        return new self(facts: []);
    }

    /**
     * The distinct (build, generation) pairs the engine may read.
     *
     * 🛑 Distinct, because two mounts of one build in one project version — a
     * component mounted twice at two paths — are two facts over the same
     * documents, and an engine given the pair twice would return every hit
     * twice. Deduplication at the filter is the cheap place to do it; after the
     * match it is a sort over a doubled result set.
     *
     * @return list<array{0: string, 1: int}> `[buildId, buildGeneration]`
     */
    public function documentKeys(): array
    {
        $seen = [];
        $keys = [];

        foreach ($this->facts as $fact) {
            $key = $fact->documentKey();

            if (isset($seen[$key])) {
                continue;
            }

            $seen[$key] = true;
            $keys[] = [$fact->buildId, $fact->buildGeneration];
        }

        return $keys;
    }

    /**
     * The facts for one (build, generation) key.
     *
     * A hit belongs to a build; which URLs it is reachable at is every fact
     * that names that build. §8.16.5's reused build has two facts and therefore
     * two URLs, and the query path emits one hit per fact — "searchable from
     * every project that mounts it".
     *
     * @return list<ScopeFact>
     */
    public function factsFor(string $buildId, int $buildGeneration): array
    {
        $key = $buildId.'@'.$buildGeneration;

        return array_values(array_filter(
            $this->facts,
            static fn (ScopeFact $fact): bool => $fact->documentKey() === $key,
        ));
    }
}
