<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Admission;

/**
 * Whether a build may start now, and — when it may not — why and how far
 * back it is.
 *
 * 🛑 The queue position is part of the decision rather than a separate
 * query, because §8.5.23 requires the UI to surface it and a second query
 * computed from a second snapshot would show a position that never existed.
 */
final readonly class AdmissionDecision
{
    private function __construct(
        public bool $admitted,

        /** A §8.5.15-shaped reason, stable, or null when admitted. */
        public ?string $reason,

        /** 1-based place in the queue; 0 when admitted. */
        public int $position,
    ) {}

    public static function admit(): self
    {
        return new self(true, null, 0);
    }

    public static function wait(string $reason, int $position): self
    {
        return new self(false, $reason, max(1, $position));
    }
}
