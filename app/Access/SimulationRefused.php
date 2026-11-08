<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

/**
 * 🛑 The simulator could not be asked, which is not the same as a denial.
 *
 * There are exactly two reasons, and both are about the *identity* rather than
 * the policy: the named row does not exist in this tenant, or it exists and has
 * been deprovisioned. In both cases a `deny` would be a true-looking sentence
 * about the wrong subject — §8.12.25's whole value is that an operator can
 * believe the answer, and an answer that silently changes the question is worse
 * than no answer.
 *
 * 🛑 §8.2.2 is why "does not exist" and "belongs to another organisation" are
 * one case rather than two: a cross-tenant reference is a 404, and
 * distinguishing the two in a message would confirm the row exists somewhere.
 */
final class SimulationRefused extends \RuntimeException
{
    private function __construct(public readonly string $reasonCode, string $message)
    {
        parent::__construct($message);
    }

    public static function noSuchIdentity(): self
    {
        return new self('no_such_identity', 'No such identity on this organisation.');
    }

    public static function deprovisioned(): self
    {
        return new self('identity_deprovisioned', 'That identity has been deprovisioned and can no longer sign in.');
    }
}
