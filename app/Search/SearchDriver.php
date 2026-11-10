<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * The two engines §8.16.1 names, and nothing else.
 *
 * > §8.16.1: "Search MUST sit behind one `SearchEngine` seam with 🛑 **MySQL
 * > InnoDB FULLTEXT as the shipped default** (no additional service —
 * > requirement §8.1.1) and **Meilisearch** selectable by one environment
 * > variable."
 *
 * 🛑 A closed enum rather than a string, because §4.2 makes semantic search,
 * Elasticsearch and Pagefind **permanently** out of scope. A string driver name
 * invites a third value; this invites an amendment.
 */
enum SearchDriver: string
{
    /** The shipped default. No service to run (§8.1.1). */
    case MysqlFulltext = 'mysql_fulltext';

    /** §8.16.1's recommendation above a measured section count. */
    case Meilisearch = 'meilisearch';

    /**
     * The driver `config/docup.php` selects, falling back to the default.
     *
     * 🛑 An unrecognised value resolves to the **default** rather than throwing.
     * A typo in `DOCUP_SEARCH_DRIVER` must not take documentation search down
     * across an installation, and the default is the one that needs no service
     * — so the failure mode of a misconfiguration is "search is slower than you
     * expected", which `doctor` reports, rather than "every reader gets a 500".
     */
    public static function configured(): self
    {
        $value = config('docup.search.driver');

        return is_string($value) ? (self::tryFrom($value) ?? self::MysqlFulltext) : self::MysqlFulltext;
    }

    /** The human name, for `doctor` and the operator UI. */
    public function label(): string
    {
        return match ($this) {
            self::MysqlFulltext => 'MySQL InnoDB FULLTEXT',
            self::Meilisearch => 'Meilisearch',
        };
    }

    /** Whether choosing this driver means running another service (§8.1.1). */
    public function needsAService(): bool
    {
        return $this === self::Meilisearch;
    }
}
