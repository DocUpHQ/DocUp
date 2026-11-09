<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Addons;

/**
 * What §8.15.9's mapping says about one Read the Docs custom property.
 *
 * 🛑 Three outcomes rather than two, and the third is the one that keeps the
 * mapping honest. A table of 33 rows all pointing at a DocUp token would read
 * as complete and mislead a migrating team in the most expensive direction:
 * they would write the override, see nothing change, and conclude the table was
 * wrong rather than that the concept does not exist here.
 *
 * {@see ReadTheDocsMapping} explains each case; this is the vocabulary, so that
 * adding a row forces a decision about which of the three it is.
 */
enum MappingKind: string
{
    /** A DocUp token covers it. The migration is a rename. */
    case Mapped = 'mapped';

    /**
     * DocUp has no token for it, deliberately.
     *
     * §8.14.1 budgets the registry at roughly forty-five tokens and Phase 27
     * dropped a forty-sixth rather than let it grow by accretion. A property
     * styling a surface DocUp's chrome does not have is a property with no
     * counterpart, and saying so is the answer.
     */
    case Covered = 'covered';

    /**
     * The feature is not built yet, so there is nothing to map.
     *
     * Distinct from {@see self::Covered} because the two are different promises:
     * `covered` will not change, and this might.
     */
    case Absent = 'absent';
}
