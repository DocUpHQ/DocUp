<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers;

/**
 * §8.12.10's handoff refusing to proceed.
 *
 * 🛑 One exception with a fixed reason vocabulary, because every one of these
 * is a 404 to the reader and a distinct audit event to the operator. §8.12.23
 * forbids the response varying with what the client sent, so the *reason* must
 * not reach the response — and keeping it on the exception rather than in the
 * message is what makes that easy to hold.
 */
final class HandoffRefused extends \RuntimeException
{
    private function __construct(
        public readonly HandoffRejection $rejection,
        string $detail,
    ) {
        parent::__construct($detail);
    }

    public static function of(HandoffRejection $rejection, string $detail = ''): self
    {
        return new self($rejection, $detail === '' ? $rejection->value : $detail);
    }
}
