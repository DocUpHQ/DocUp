<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * §8.16.12's three scope filters, closed.
 *
 * The case for `self:me` is named `Accessible` rather than `Self`: `self` is a
 * reserved word in PHP and an enum case cannot carry it, so the wire value and
 * the case name differ here and only here. `value` is what §8.16.12 writes.
 */
enum ScopeKind: string
{
    /** `project:<slug>[/<version>]`. */
    case Project = 'project';

    /** `collection:<slug>` — §8.16.10's cross-project search is Phase 30's. */
    case Collection = 'collection';

    /** `self:me` — "the reader's own accessible set". */
    case Accessible = 'self';
}
