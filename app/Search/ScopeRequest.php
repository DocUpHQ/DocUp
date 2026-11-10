<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * One of §8.16.12's three scope filters, as the reader asked for it.
 *
 * > §8.16.12: "the scope filters `project:<slug>[/<version>]`,
 * > `collection:<slug>` and `self:me` (the reader's own accessible set)."
 *
 * 🛑 **A request, never a filter.** The slug here came off a query string. It
 * names something the reader *hopes* to search; whether it exists, and whether
 * they may read it, is `EffectiveAccess`'s answer and nobody else's. A request
 * for a project the reader cannot read narrows the result set to nothing —
 * never widens it, and never reveals that the project exists, because an
 * unreadable project and a non-existent one produce the same empty set.
 */
final readonly class ScopeRequest
{
    /**
     * @param  ScopeKind  $kind  which of the three
     * @param  string  $slug  the project or collection slug as typed; empty for
     *                        {@see ScopeKind::Accessible}
     * @param  string|null  $version  the optional `/<version>` half of
     *                                `project:<slug>/<version>`
     */
    public function __construct(
        public ScopeKind $kind,
        public string $slug,
        public ?string $version = null,
    ) {}
}
