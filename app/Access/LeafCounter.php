<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

/**
 * A leaf tally carried through {@see Requirement}'s recursive validation.
 *
 * A mutable object rather than a reference parameter, because the recursion
 * passes it down several branches and a by-reference `int` through a `static`
 * method is the kind of thing Larastan is right to be suspicious of. Small
 * enough to be obvious; the alternative was returning a count from every
 * validation call and summing it at each node, which buries the cap in
 * arithmetic.
 */
final class LeafCounter
{
    private int $count = 0;

    public function increment(): void
    {
        $this->count++;
    }

    public function count(): int
    {
        return $this->count;
    }
}
