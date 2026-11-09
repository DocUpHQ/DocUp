<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Values;

use App\Branding\BrandingToken;
use App\Branding\ForbiddenFunctions;
use App\Branding\TokenRefused;
use App\Branding\TokenRejection;

/**
 * §8.14.2's length grammar: "a clamped number plus an allowlisted unit".
 *
 * 🛑 **Clamped rather than merely validated.** The requirement's word is
 * "clamped", and the registry entry carries the bounds
 * ({@see BrandingToken::$minimum}) — but a value outside them is **refused**
 * here rather than silently pulled inside. Clamping a 9000px sidebar to 600px
 * would store a number the operator did not write and did not ask for, and the
 * next person to read the theme would see a value nobody chose. The bound is
 * the clamp; the refusal is how the operator learns where it is.
 *
 * 🛑 **`0` is accepted without a unit and nothing else is.** CSS treats a bare
 * zero as a length and treats a bare `12` as an error, so accepting unitless
 * non-zero numbers would let a theme save a declaration a browser drops.
 */
final readonly class LengthValue implements TokenValue
{
    /**
     * The units a branding length may carry.
     *
     * 🛑 `vw`, `vh`, `vmin`, `vmax` and `svh` are absent. A viewport unit in a
     * chrome token is a layout that collapses on a phone or overlaps the
     * reader's content at a zoom level nobody tested, and the tokens that
     * genuinely want a proportion of the viewport use `%`. `pt`, `pc`, `in`,
     * `cm` and `mm` are absent because this is a screen theme and a physical
     * unit on screen means whatever the user agent decides it means.
     *
     * @var list<string>
     */
    private const UNITS = ['px', 'rem', 'em', 'ch', '%'];

    private function __construct(
        public float $magnitude,
        public string $unit,
    ) {}

    /**
     * @param  string  $path  the token name, for the rejection
     *
     * @throws TokenRefused
     */
    public static function parse(string $raw, string $path, float $minimum, float $maximum): self
    {
        $raw = strtolower(trim($raw));

        ForbiddenFunctions::assertAbsent($raw, $path);

        if ($raw === '0') {
            return new self(0.0, 'px');
        }

        if (preg_match('/^(\d+(?:\.\d+)?|\.\d+)([a-z%]+)$/', $raw, $matches) !== 1) {
            throw TokenRefused::of(
                TokenRejection::WrongType,
                $path,
                'a length is a positive number and one of '.implode(', ', self::UNITS),
            );
        }

        [, $number, $unit] = $matches;

        if (! in_array($unit, self::UNITS, true)) {
            throw TokenRefused::of(
                TokenRejection::DisallowedUnit,
                $path,
                sprintf('%s is not an allowed unit; use one of %s', $unit, implode(', ', self::UNITS)),
            );
        }

        $magnitude = (float) $number;

        if ($magnitude < $minimum || $magnitude > $maximum) {
            throw TokenRefused::of(
                TokenRejection::NumericOutOfRange,
                $path,
                sprintf('%s is outside the permitted %s to %s', $number, self::trim($minimum), self::trim($maximum)),
            );
        }

        return new self($magnitude, $unit);
    }

    public function serialise(): string
    {
        return $this->magnitude === 0.0 ? '0' : self::trim($this->magnitude).$this->unit;
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
