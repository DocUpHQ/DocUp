<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * The answer to one search: results, and **why** there are none when there are
 * none.
 *
 * 🛑 The second half is the part that matters. §8.12.21 makes "search is
 * disabled because the index lags the policy" a different fact from "nothing
 * matched", and a return type that could only say `[]` would conflate them —
 * which is how a project whose search has been off for a week gets reported as
 * a project with an empty corpus.
 *
 * {@see self::$state} is what a surface renders and what `doctor` reports. The
 * reader is told the same thing in every denying case, because §8.12.23's
 * reasoning applies to a result set: "no results" and "no results you may see"
 * must look identical or the empty set becomes an oracle. It is the
 * **operator** who gets the distinction.
 */
final readonly class SearchOutcome
{
    /**
     * @param  list<SearchResult>  $results
     * @param  SearchState  $state  why the list looks as it does
     */
    public function __construct(
        public array $results,
        public SearchState $state,
        public SearchDriver $driver,
    ) {}

    /**
     * §8.15.8's payload shape, as the chrome runtime reads it.
     *
     * 🛑 `results` and nothing else. {@see SearchState} is for the operator and
     * is deliberately absent from anything a reader could receive: §8.12.23's
     * reasoning applies to a result set, so "no results" and "no results you
     * may see" must look identical or the empty set becomes an oracle for what
     * exists.
     *
     * @return array{results: list<array{title: string, href: string, project: string, version: string, page: string, section: string, excerpt: string}>}
     */
    public function toPayload(): array
    {
        return [
            'results' => array_map(
                static fn (SearchResult $result): array => $result->toPayload(),
                $this->results,
            ),
        ];
    }

    public function isEmpty(): bool
    {
        return $this->results === [];
    }
}
