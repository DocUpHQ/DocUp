<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

/**
 * What one verification attempt concluded.
 *
 * 🛑 `$passed` and `$outcome` are different facts and both are needed. A
 * check can fail because the record is gone (`Answered`, not passed) or
 * because nothing answered (`Unresolvable`, not passed), and §8.10.6's state
 * machine must advance on the first and stand still on the second. A single
 * boolean would collapse them and start a seven-day suspension clock on
 * every domain in the installation during a resolver outage.
 */
final readonly class VerificationResult
{
    public function __construct(
        public bool $passed,
        public VerificationMethod $method,
        public Outcome $outcome,
        public string $detail = '',
    ) {}

    /**
     * Whether this result should move the domain's state at all.
     *
     * An unresolvable check is not evidence about the domain; it is evidence
     * about the resolvers.
     */
    public function isConclusive(): bool
    {
        return $this->passed || $this->outcome !== Outcome::Unresolvable;
    }
}
