<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Redirects;

use App\Support\Invalidation;

/**
 * One project's rules, in position order, as the engine evaluates them.
 *
 * 🛑 **One query, and the exit criterion is about this class.** §17's Phase
 * 20 criterion is "a 1,000-redirect project resolves in **one query** under
 * 10 ms", which rules out the obvious implementation — ask the database
 * which rule matches — because no index can answer "which of these patterns
 * matches this string". So the rules are loaded whole, once, and matched in
 * PHP.
 *
 * That also buys §8.11.4's evaluation cap: a count of regex evaluations is
 * only meaningful if the evaluating happens somewhere we can count it.
 *
 * 🛑 Cached on `routing_epoch`, the same key §8.9.10 gives every other
 * resolution cache, so a rule change takes effect by addressing a different
 * key rather than by purging. {@see Invalidation} is the only
 * thing that moves the epoch.
 */
final readonly class RedirectSet
{
    /**
     * @param  list<array{id: string, position: int, kind: string, forced: bool, from: string, to: string, status: int}>  $rules
     */
    public function __construct(
        public array $rules,
        public bool $regexEnabled,
    ) {}

    public static function empty(): self
    {
        return new self([], RegexGuard::enabled());
    }

    public function isEmpty(): bool
    {
        return $this->rules === [];
    }

    /**
     * The rules for one pass of §8.11.1's order.
     *
     * @return list<array{id: string, position: int, kind: string, forced: bool, from: string, to: string, status: int}>
     */
    public function pass(bool $forced): array
    {
        return array_values(array_filter(
            $this->rules,
            static fn (array $rule): bool => $rule['forced'] === $forced,
        ));
    }
}
