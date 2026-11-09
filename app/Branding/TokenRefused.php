<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

/**
 * A branding value the grammar, the cascade or the asset pipeline refused.
 *
 * 🛑 **Throws rather than returns a list of problems.** Phase 26b's build-log
 * entry records why, on a driver that had made the other choice: "A driver
 * reporting its own configuration errors as data is a driver whose caller has
 * to decide what a non-empty return means." Here the stakes are the same —
 * a caller that treated an empty-ish return as success would store an
 * unvalidated colour, and §8.14.2's whole claim is that nothing unparsed is
 * ever emitted.
 *
 * 🛑 **The `path` is the token name, not a message to parse.** A UI showing
 * which field is wrong needs the field; a message needs prose. Keeping them in
 * separate properties is what lets the dashboard highlight a row without
 * string-matching an exception.
 */
final class TokenRefused extends \RuntimeException
{
    private function __construct(
        public readonly TokenRejection $rejection,
        public readonly string $path,
        string $message,
    ) {
        parent::__construct($message);
    }

    /**
     * @param  string  $path  the token name, or a dotted path into chrome content
     * @param  string  $detail  what was wrong, in words an operator can act on
     */
    public static function of(TokenRejection $rejection, string $path, string $detail = ''): self
    {
        $message = $path === ''
            ? $rejection->value
            : $path.': '.$rejection->value;

        return new self($rejection, $path, $detail === '' ? $message : $message.' — '.$detail);
    }
}
