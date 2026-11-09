<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Values;

use App\Branding\TokenRefused;
use App\Branding\TokenRejection;

/**
 * One value from a token's closed option list.
 *
 * 🛑 The option list lives in the registry entry, not here, so the operator
 * documentation's table can print it and so a plugin adding a token brings its
 * own options with it (§8.14.1's "plugin-extendable"). A type that held the
 * options would make every new enumerated token a change to this class.
 */
final readonly class OptionValue implements TokenValue
{
    private function __construct(public string $value) {}

    /**
     * @param  list<string>  $options  from the registry entry
     * @param  string  $path  the token name, for the rejection
     *
     * @throws TokenRefused
     */
    public static function parse(string $raw, string $path, array $options): self
    {
        $value = strtolower(trim($raw));

        if (! in_array($value, $options, true)) {
            throw TokenRefused::of(
                TokenRejection::NotAnOption,
                $path,
                sprintf('%s is not one of %s', $value === '' ? '(empty)' : $value, implode(', ', $options)),
            );
        }

        return new self($value);
    }

    public function serialise(): string
    {
        return $this->value;
    }

    public function toStorage(): string
    {
        return $this->value;
    }
}
