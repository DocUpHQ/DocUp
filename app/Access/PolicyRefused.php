<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

/**
 * A reader policy, rule or requirement that will not be saved.
 *
 * Thrown rather than returned, for the reason `RedirectRefused`,
 * `DomainRefused` and `EgressRefused` are: a result object that must be
 * inspected is one somebody eventually does not inspect — and what goes
 * unchecked here is §8.12.7's satisfiability invariant, whose failure mode is
 * an IP allowlist standing in for authentication.
 */
final class PolicyRefused extends \RuntimeException
{
    public function __construct(
        public readonly RequirementRejection $rejection,
        public readonly string $detail = '',
        ?\Throwable $previous = null,
    ) {
        parent::__construct($rejection->value.($detail === '' ? '' : ': '.$detail), 0, $previous);
    }

    public static function of(
        RequirementRejection $rejection,
        string $detail = '',
        ?\Throwable $previous = null,
    ): self {
        return new self($rejection, $detail, $previous);
    }

    public function identifier(): string
    {
        return $this->rejection->value;
    }
}
