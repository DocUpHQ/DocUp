<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

/**
 * One rung of §8.14.1's cascade, already parsed.
 *
 * 🛑 **Parsed, not raw.** A layer reaches {@see ThemeCascade} as
 * {@see TokenPair} objects, so the cascade never touches a string an operator
 * typed and cannot be the place a grammar is skipped. §8.14.2's
 * re-serialisation requirement is structural rather than remembered: the only
 * way to build a layer is through {@see TokenGrammar}.
 */
final readonly class ThemeLayer
{
    /**
     * @param  array<string, TokenPair>  $tokens  this level's own values only
     * @param  string|null  $revisionId  which `theme_revisions` row, for provenance
     */
    public function __construct(
        public CascadeLevel $level,
        public array $tokens,
        public ThemeLocks $locks,
        public ?string $revisionId = null,
    ) {}

    public static function empty(CascadeLevel $level): self
    {
        return new self($level, [], ThemeLocks::none());
    }
}
