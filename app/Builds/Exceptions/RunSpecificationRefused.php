<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Exceptions;

/**
 * A run specification the runner will not execute (§8.5.13).
 *
 * 🛑 It carries a **reason code**, not just a message, because the two
 * refusals this distinguishes need different words in front of an operator:
 * a malformed field is somebody's bug, and a document asking for a
 * container privilege is somebody's attempt. Matching on the message text
 * to tell them apart — which is what the first version did — makes the
 * identifier depend on the wording, and §8.5.15 requires identifiers to be
 * stable while messages are reworded freely.
 *
 * Extends `InvalidArgumentException` so every existing `catch` around the
 * typed specification keeps working; what is added is the code, not a new
 * failure path.
 */
final class RunSpecificationRefused extends \InvalidArgumentException
{
    private function __construct(
        /** The second half of a §8.5.15 identifier, under the `rejected` class. */
        public readonly string $reason,
        string $message,
    ) {
        parent::__construct($message);
    }

    /** A document asking for a mount, a capability or the runtime socket. */
    public static function privilegeSought(string $field): self
    {
        return new self(
            'runtime_socket_requested',
            "a run specification may not request container privileges: {$field} (§8.5.13)",
        );
    }

    /** Any other field the typed specification does not declare. */
    public static function unknownField(string $field): self
    {
        return new self('run_specification_refused', "unknown run specification field: {$field}");
    }
}
