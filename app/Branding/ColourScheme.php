<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

/**
 * Which of a paired colour token's two values is in play.
 *
 * Two cases and not three: `system` is a value of the `scheme.default` token,
 * which says what a reader sees when they have expressed no preference. It is
 * not a third palette, and a type that admitted it would invite somebody to
 * ask what a `system` colour is.
 */
enum ColourScheme: string
{
    case Light = 'light';

    case Dark = 'dark';

    /**
     * Both, in report order.
     *
     * @return list<self>
     */
    public static function both(): array
    {
        return [self::Light, self::Dark];
    }

    /**
     * The backdrop a translucent colour composites over when the gate has no
     * better backdrop to hand (§8.14.5).
     *
     * White in light and black in dark: the extremes, which is the
     * conservative choice because it maximises the chance that a translucent
     * colour is measured as lower-contrast than it will look. A gate that
     * guessed a flattering backdrop would pass themes that fail.
     *
     * @return array{float, float, float}
     */
    public function fallbackBackdrop(): array
    {
        return $this === self::Light ? [1.0, 1.0, 1.0] : [0.0, 0.0, 0.0];
    }
}
