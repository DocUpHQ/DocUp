<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * Stable identifiers for every §8.16 refusal.
 *
 * 🛑 **Stable and distinct**, for the reason `App\Egress\EgressRejection`
 * states: these strings reach operator alerts, `doctor` output and runbooks, so
 * they are added to and never edited — and a single `search.failed` would let
 * three unrelated faults rot behind the one somebody noticed.
 */
enum SearchRejection: string
{
    /** The configured engine could not be reached. */
    case EngineUnreachable = 'search.engine_unreachable';

    /** The engine answered, and said no. */
    case EngineRefused = 'search.engine_refused';

    /**
     * 🛑 §8.16.8's filterable set did not match what the index was built with.
     *
     * Refused rather than repaired, because repairing it means a full reindex
     * and §8.16.8's whole point is that a `filterableAttributes` change "forces
     * a mandatory full reindex, which makes any later addition a migration
     * event (§15.5)". So an index whose declared attributes differ from this
     * release's is an **upgrade step an operator must run**, surfaced as one,
     * rather than a reindex the application starts by itself on a Tuesday.
     */
    case FilterSetChanged = 'search.filter_set_changed';

    /** A build's artifact could not be read, so nothing could be extracted. */
    case ArtifactUnreadable = 'search.artifact_unreadable';

    /**
     * A generator's structured index was present and unusable.
     *
     * Not fatal to the pass: §8.16.4 says the system "SHOULD ingest it rather
     * than re-parsing HTML", so an unusable one falls back to §8.16.3's HTML
     * extraction and this identifier is what says so in the log.
     */
    case StructuredIndexUnusable = 'search.structured_index_unusable';

    /** One line, for the operator. */
    public function reason(): string
    {
        return match ($this) {
            self::EngineUnreachable => 'the configured search engine did not answer',
            self::EngineRefused => 'the search engine rejected the request',
            self::FilterSetChanged => 'the index declares a different filterable attribute set; a full reindex is required (§8.16.8)',
            self::ArtifactUnreadable => "the build's artifact could not be read",
            self::StructuredIndexUnusable => "the generator's structured index could not be parsed",
        };
    }
}
