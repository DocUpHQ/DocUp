<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Values;

use App\Branding\TokenRefused;
use App\Branding\TokenRejection;

/**
 * A boolean token.
 *
 * 🛑 Serialises as `1` or `0`, not as `true`/`false`. The stylesheet writer
 * emits custom properties, and chrome reads some of them through
 * `@container style(--docup-x: 1)` and through a CSS `if()`-style guard; a
 * property whose value is the word `true` is a string a selector cannot test
 * numerically. The JSON payload gets the real boolean from
 * {@see self::toStorage()}, so the two consumers each get the shape they need
 * from one parsed value.
 */
final readonly class FlagValue implements TokenValue
{
    private function __construct(public bool $value) {}

    /**
     * @param  string  $path  the token name, for the rejection
     *
     * @throws TokenRefused
     */
    public static function parse(string $raw, string $path): self
    {
        return match (strtolower(trim($raw))) {
            'true', '1', 'yes', 'on' => new self(true),
            'false', '0', 'no', 'off' => new self(false),
            default => throw TokenRefused::of(TokenRejection::WrongType, $path, 'a flag is true or false'),
        };
    }

    public function serialise(): string
    {
        return $this->value ? '1' : '0';
    }

    public function toStorage(): bool
    {
        return $this->value;
    }
}
