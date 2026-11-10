<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * A refusal by §8.16's indexer or by an engine.
 *
 * 🛑 Thrown on the **indexing** path and never on the reader's. §8.16.1 makes
 * the default engine serviceless so that the optional one's outage is
 * survivable, and that promise is only kept if a query path treats an
 * unreachable engine as an empty result set with a stated reason rather than as
 * an exception — a 500 on every documentation page that carries a search box is
 * a worse outcome than a search box that says search is unavailable.
 *
 * `SearchQuery` therefore catches this and `SearchArchitectureTest` asserts no
 * controller lets it escape.
 *
 * 🛑 The message carries the rejection identifier and a build id at most. No
 * query string, ever: a reader's query is their own and a search term in an
 * exception message is a search term in the error tracker.
 */
final class SearchRefused extends \RuntimeException
{
    /** @param  array<string, mixed>  $context  identifiers and counts only; never a query or a document */
    public function __construct(
        public readonly SearchRejection $rejection,
        public readonly array $context = [],
    ) {
        parent::__construct($rejection->value.': '.$rejection->reason());
    }

    /** The stable identifier, for an API response or an audit record. */
    public function identifier(): string
    {
        return $this->rejection->value;
    }
}
