<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers;

use App\Access\PolicyRefused;

/**
 * A binding write refused at validation.
 *
 * 🛑 One exception with a fixed reason vocabulary, like §8.12.7's
 * {@see PolicyRefused}. The reason codes are §8.1.11 public
 * contract — they reach an operator's form and the API's error bodies — so they
 * are an enum rather than a message, and renaming one is a contract change.
 */
final class BindingRefused extends \RuntimeException
{
    private function __construct(
        public readonly BindingRejection $rejection,
        string $detail,
    ) {
        parent::__construct($detail);
    }

    public static function of(BindingRejection $rejection, string $detail = ''): self
    {
        return new self($rejection, $detail === '' ? $rejection->value : $detail);
    }
}
