<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

/**
 * What {@see CompositionCollisions} found: §8.7.14's collisions and
 * §8.7.15's shadowed paths, kept apart.
 *
 * Two sets rather than one, because the remedies differ. A collision is a
 * composition the operator has to change; a shadowed path is one they
 * already chose to accept by setting the override, and the redirects are
 * what makes that choice survivable for a reader with a bookmark.
 */
final readonly class CompositionOverlap
{
    /**
     * @param  list<PathCollision>  $collisions
     * @param  array<string, string>  $shadowRedirects  shadowed URL => target URL,
     *                                                  both relative to the version root
     * @param  int  $shadowOverflow  how many shadowed paths exceeded the cap
     */
    public function __construct(
        public array $collisions,
        public array $shadowRedirects,
        public int $shadowOverflow = 0,
    ) {}

    public function clean(): bool
    {
        return $this->collisions === [];
    }
}
