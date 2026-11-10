<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * Why a search returned what it returned.
 *
 * 🛑 For the **operator**, not for the reader. A reader sees the same empty
 * list whichever of the denying states produced it — §8.12.23's reasoning
 * applied to a result set, because an empty set that explains itself is an
 * oracle for what exists.
 */
enum SearchState: string
{
    /** The engine answered and the list is the answer. */
    case Answered = 'answered';

    /** Nothing to search: no terms, or only stopwords and short tokens. */
    case EmptyQuery = 'empty_query';

    /**
     * 🛑 §8.12.21: the project's search generation lags its policy generation,
     * so search is **disabled** rather than stale.
     *
     * The one state an operator must be able to see, because it is a condition
     * that persists until a reindex runs and looks like an empty corpus from
     * every other angle.
     */
    case GenerationStale = 'generation_stale';

    /** The project has never been indexed. */
    case NotIndexed = 'not_indexed';

    /** This reader may search nothing here. */
    case NotAuthorised = 'not_authorised';

    /**
     * §8.16.1's optional engine is configured and did not answer.
     *
     * Not an exception: the default engine needs no service precisely so that
     * the optional one's outage is survivable, and a 500 on every documentation
     * page carrying a search box would be the worse outage.
     */
    case EngineUnavailable = 'engine_unavailable';

    /** One line, for `doctor` and the operator UI. */
    public function reason(): string
    {
        return match ($this) {
            self::Answered => 'the engine answered',
            self::EmptyQuery => 'the query held no searchable term',
            self::GenerationStale => 'search is disabled: the index predates the current policy (§8.12.21)',
            self::NotIndexed => 'this project has never been indexed',
            self::NotAuthorised => 'this reader may search nothing here',
            self::EngineUnavailable => 'the configured search engine did not answer',
        };
    }

    /** Whether an operator should be told about this one. */
    public function isOperatorConcern(): bool
    {
        return match ($this) {
            self::GenerationStale, self::NotIndexed, self::EngineUnavailable => true,
            default => false,
        };
    }
}
