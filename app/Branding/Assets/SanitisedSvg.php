<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Assets;

/**
 * The result of §8.14.11's SVG sanitisation: the bytes, and what went.
 *
 * 🛑 **The removals are part of the result, not a log line.** An operator
 * whose logo arrived without its drop shadow needs to know that the filter was
 * dropped, and an operator whose design tool emitted an `onload` needs to know
 * that too — for different reasons, and both are unanswerable if the
 * sanitiser's decisions are discarded. The upload response carries them.
 */
final readonly class SanitisedSvg
{
    /**
     * @param  string  $svg  the re-serialised document
     * @param  list<string>  $removed  elements and attributes not copied
     */
    public function __construct(
        public string $svg,
        public array $removed,
    ) {}

    public function wasAltered(): bool
    {
        return $this->removed !== [];
    }
}
