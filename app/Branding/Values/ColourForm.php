<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Values;

/**
 * The colour notations §8.14.2 admits, and no others.
 *
 * 🛑 The list is closed and it is short. `color()`, `lab()`, `color-mix()`,
 * `light-dark()` and the named keywords are all absent — not because they are
 * dangerous, but because every notation is a parser DocUp has to keep correct
 * and a gamut it has to convert from for the §8.14.5 contrast gate. A colour
 * the contrast gate cannot reduce to sRGB is a colour the gate silently skips,
 * and a skipped pair is a pair that passes.
 */
enum ColourForm: string
{
    /** `#rgb`, expanded on parse; three components, alpha 1. */
    case HexShort = 'hex_short';

    /** `#rrggbb`. */
    case Hex = 'hex';

    /** `#rrggbbaa`. */
    case HexAlpha = 'hex_alpha';

    /** `rgb()`, legacy or modern syntax, with or without alpha. */
    case Rgb = 'rgb';

    /** `hsl()`, legacy or modern syntax, with or without alpha. */
    case Hsl = 'hsl';

    /** `oklch()`. */
    case Oklch = 'oklch';
}
