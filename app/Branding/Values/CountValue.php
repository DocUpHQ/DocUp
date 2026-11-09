<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Values;

use App\Branding\ForbiddenFunctions;
use App\Branding\TokenRefused;
use App\Branding\TokenRejection;

/** A bounded integer — a font weight, a stacking order, a column count. */
final readonly class CountValue implements TokenValue
{
    private function __construct(public int $value) {}

    /**
     * @param  string  $path  the token name, for the rejection
     *
     * @throws TokenRefused
     */
    public static function parse(string $raw, string $path, int $minimum, int $maximum): self
    {
        $raw = trim($raw);

        ForbiddenFunctions::assertAbsent($raw, $path);

        if (preg_match('/^\d+$/', $raw) !== 1) {
            throw TokenRefused::of(TokenRejection::WrongType, $path, 'an integer with no sign and no decimal point');
        }

        $value = (int) $raw;

        if ($value < $minimum || $value > $maximum) {
            throw TokenRefused::of(
                TokenRejection::NumericOutOfRange,
                $path,
                sprintf('%d is outside the permitted %d to %d', $value, $minimum, $maximum),
            );
        }

        return new self($value);
    }

    public function serialise(): string
    {
        return (string) $this->value;
    }

    public function toStorage(): int
    {
        return $this->value;
    }
}
