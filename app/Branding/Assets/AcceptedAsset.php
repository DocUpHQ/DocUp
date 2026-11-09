<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Assets;

use App\Models\ThemeAsset;

/**
 * The result of one §8.14.11 upload.
 *
 * 🛑 `$removed` travels with the row because an operator whose SVG lost its
 * drop shadow and an operator whose SVG lost an `onload` both need to be told,
 * and neither can be told from a row alone. `$deduplicated` is there so the
 * dashboard can say "you already had this one" rather than appearing to do
 * nothing.
 */
final readonly class AcceptedAsset
{
    /** @param list<string> $removed what the sanitiser did not copy */
    public function __construct(
        public ThemeAsset $asset,
        public array $removed = [],
        public bool $deduplicated = false,
    ) {}
}
