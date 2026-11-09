<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

use App\Branding\Values\TokenValue;

/**
 * One token's value in both colour schemes (§8.14.7's "explicit pairs").
 *
 * 🛑 **A pair is overridden as a pair.** A deeper cascade level that sets
 * `color.surface.page` sets both schemes, and there is no spelling by which it
 * sets light and inherits dark. That is the whole reason this type exists
 * rather than two parallel maps: inheriting half a pair produces a palette
 * nobody designed, and the §8.14.5 gate would then be judging a dark scheme
 * that is one level's light values beside another level's dark ones.
 *
 * An unpaired token has the same value in both schemes, so {@see self::$light}
 * and {@see self::$dark} are the same object. Nothing has to ask which it is.
 */
final readonly class TokenPair
{
    public function __construct(
        public TokenValue $light,
        public TokenValue $dark,
    ) {}

    /** Both schemes share one value. */
    public static function same(TokenValue $value): self
    {
        return new self($value, $value);
    }

    public function for(ColourScheme $scheme): TokenValue
    {
        return $scheme === ColourScheme::Light ? $this->light : $this->dark;
    }

    /** Whether the two schemes differ, which decides whether the dark block emits. */
    public function differs(): bool
    {
        return $this->light->serialise() !== $this->dark->serialise();
    }
}
