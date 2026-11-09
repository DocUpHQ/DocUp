<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Chrome;

/**
 * §8.14.3's announcement, after {@see InlineMarkup} has been through it.
 *
 * 🛑 `$markup` is the only field in the whole of §8.14.3's structured content
 * that is markup rather than data, and it holds only what the five-element
 * allowlist admits — written by DocUp, never echoed from the input.
 */
final readonly class Announcement
{
    /** @param list<string> $removed what the allowlist did not admit */
    public function __construct(
        public string $markup,
        public array $removed = [],
    ) {}
}
