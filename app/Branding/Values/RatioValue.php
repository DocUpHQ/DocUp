<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Values;

use App\Branding\ForbiddenFunctions;
use App\Branding\TokenRefused;
use App\Branding\TokenRejection;

/**
 * A bounded unitless number — a type scale, a line height.
 *
 * 🛑 Its own type rather than a {@see LengthValue} with no unit, because CSS
 * distinguishes them and so does meaning: `line-height: 1.5` is a multiple of
 * the font size and `line-height: 1.5rem` is a fixed distance that stops
 * scaling when the reader enlarges the text. §9.5's WCAG 2.2 AA posture makes
 * that difference an accessibility one, not a stylistic one.
 */
final readonly class RatioValue implements TokenValue
{
    private function __construct(public float $value) {}

    /**
     * @param  string  $path  the token name, for the rejection
     *
     * @throws TokenRefused
     */
    public static function parse(string $raw, string $path, float $minimum, float $maximum): self
    {
        $raw = trim($raw);

        ForbiddenFunctions::assertAbsent($raw, $path);

        if (preg_match('/^(?:\d+(?:\.\d+)?|\.\d+)$/', $raw) !== 1) {
            throw TokenRefused::of(TokenRejection::WrongType, $path, 'a ratio is a plain positive decimal');
        }

        $value = (float) $raw;

        if ($value < $minimum || $value > $maximum) {
            throw TokenRefused::of(
                TokenRejection::NumericOutOfRange,
                $path,
                sprintf('%s is outside the permitted %s to %s', $raw, self::trim($minimum), self::trim($maximum)),
            );
        }

        return new self($value);
    }

    public function serialise(): string
    {
        return self::trim($this->value);
    }

    public function toStorage(): string
    {
        return $this->serialise();
    }

    private static function trim(float $value): string
    {
        $text = rtrim(rtrim(sprintf('%.4F', $value), '0'), '.');

        return $text === '' ? '0' : $text;
    }
}
