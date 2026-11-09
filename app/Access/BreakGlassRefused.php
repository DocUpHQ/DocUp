<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

/**
 * A break-glass activation refused, carrying its reason as a
 * {@see BreakGlassRejection}.
 *
 * 🛑 Unlike every other refusal in this namespace, this one is **meant to be
 * shown**. §8.12.23's silence protects a reader from learning that a private
 * resource exists; the person reading this is an installation owner who already
 * knows, and who needs to be told which of §8.12.20's four preconditions they
 * have not met.
 */
final class BreakGlassRefused extends \RuntimeException
{
    private function __construct(
        public readonly BreakGlassRejection $rejection,
        public readonly string $detail,
    ) {
        parent::__construct($rejection->explain().($detail === '' ? '' : ' ('.$detail.')'));
    }

    public static function of(BreakGlassRejection $rejection, string $detail = ''): self
    {
        return new self($rejection, $detail);
    }
}
