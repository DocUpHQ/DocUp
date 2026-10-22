<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

/**
 * One document's injection result.
 *
 * 🛑 `bytes` is always set, injected or not. §8.15.4 is explicit that a
 * non-injectable artifact is still **published** — it falls back to
 * `chrome_mode: api_only` for that build, and "a reader of a non-injectable
 * artifact gets no injected chrome". Refusing to store the document would turn
 * a cosmetic shortfall into a missing page, which is not what the requirement
 * asks for and is much worse for the reader.
 */
final class Injection
{
    private function __construct(
        public readonly InjectionOutcome $outcome,
        public readonly string $bytes,
    ) {}

    public static function injected(string $bytes): self
    {
        return new self(InjectionOutcome::Injected, $bytes);
    }

    /** Not injected, and the original bytes are stored unchanged. */
    public static function refused(InjectionOutcome $outcome, string $bytes): self
    {
        return new self($outcome, $bytes);
    }

    public function wasInjected(): bool
    {
        return $this->outcome === InjectionOutcome::Injected;
    }
}
