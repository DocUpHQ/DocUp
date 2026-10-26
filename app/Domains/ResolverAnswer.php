<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

/**
 * One agreed lookup, with what each resolver actually said.
 *
 * `$observed` is carried so a failing check can be debugged without
 * reproducing it — §8.10.6 requires every check to be recorded, and a record
 * that says only "failed" sends an operator to `dig` to find out what DocUp
 * saw, which is the question the record was supposed to answer.
 */
final readonly class ResolverAnswer
{
    /**
     * @param  list<string>  $values  agreed and sorted; empty unless Answered
     * @param  array<string, list<string>|null>  $observed  per resolver; null means it did not answer
     */
    public function __construct(
        public Outcome $outcome,
        public array $values,
        public array $observed,
    ) {}

    public function agreed(): bool
    {
        return $this->outcome === Outcome::Answered;
    }

    /** Whether the agreed answer contains this exact value. */
    public function contains(string $value): bool
    {
        return $this->agreed() && in_array($value, $this->values, true);
    }
}
