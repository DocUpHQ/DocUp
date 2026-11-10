<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * One row of §8.16.12's "published capability matrix".
 *
 * > §8.16.12: "Syntax a driver cannot support — typo tolerance, prefix,
 * > proximity, fuzziness — MUST be documented per driver in a published
 * > capability matrix and MUST degrade to a literal term rather than erroring."
 *
 * 🛑 The matrix is **generated from the drivers** rather than written beside
 * them. A hand-kept table is a table that disagrees with the code the first
 * time a driver changes, and the thing a migrating team reads before choosing
 * an engine must not be the stale copy.
 */
enum EngineCapability: string
{
    /** §8.16.12's floor: implicit AND between terms. Both engines owe it. */
    case ImplicitAnd = 'implicit_and';

    /** §8.16.12's floor: exact phrase in double quotes. Both engines owe it. */
    case ExactPhrase = 'exact_phrase';

    /** §8.16.12's floor: the three scope filters. Both engines owe it. */
    case ScopeFilters = 'scope_filters';

    /** §8.16.2: MySQL has none; Meilisearch does. */
    case TypoTolerance = 'typo_tolerance';

    /** Prefix matching — `auth` finding `authentication`. */
    case Prefix = 'prefix';

    /** Proximity ranking — terms near each other scoring higher. */
    case Proximity = 'proximity';

    /** §8.16.2: `deploying` matching `deploy`. */
    case Stemming = 'stemming';

    /** Per-field weighting beyond what a FULLTEXT index can express. */
    case FieldWeights = 'field_weights';

    /** §8.16.10's result highlighting — Phase 30's surface, the engine's ability. */
    case Highlighting = 'highlighting';

    /** One line for the published matrix. */
    public function label(): string
    {
        return match ($this) {
            self::ImplicitAnd => 'Implicit AND between terms',
            self::ExactPhrase => 'Exact phrase in double quotes',
            self::ScopeFilters => 'Scope filters (project, collection, self)',
            self::TypoTolerance => 'Typo tolerance',
            self::Prefix => 'Prefix matching',
            self::Proximity => 'Proximity ranking',
            self::Stemming => 'Stemming',
            self::FieldWeights => 'Per-field weighting',
            self::Highlighting => 'Result highlighting',
        };
    }

    /**
     * 🛑 Whether §8.16.12's minimum syntax requires it of **every** driver.
     *
     * The three that are required are the three the claim "the identical suite
     * passes on both engines" rests on. A driver that could not do one of them
     * would not be a driver with a documented gap; it would make the exit
     * criterion false, and `EngineContractTest` asserts each driver reports all
     * three.
     */
    public function isRequiredOfEveryDriver(): bool
    {
        return match ($this) {
            self::ImplicitAnd, self::ExactPhrase, self::ScopeFilters => true,
            default => false,
        };
    }
}
