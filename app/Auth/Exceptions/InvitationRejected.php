<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Exceptions;

use App\Auth\Scope;
use App\Models\Invitation;

/**
 * An invitation could not be issued or accepted (§8.2.4).
 *
 * 🛑 The messages are deliberately uneven, and that unevenness is the design.
 * An administrator issuing an invitation gets a precise reason. Someone
 * presenting a code gets as little as possible: {@see self::unknownCode()} and
 * {@see self::wrongRecipient()} are worded identically, because distinguishing
 * them tells an attacker holding a leaked code whether it is live and whose
 * address it is bound to — turning a useless string into a target.
 */
final class InvitationRejected extends \RuntimeException
{
    public static function unknownCode(): self
    {
        return new self('That invitation is not valid.');
    }

    public static function wrongRecipient(): self
    {
        // Identical wording to unknownCode() on purpose. See the class note.
        return new self('That invitation is not valid.');
    }

    /** Safe to be specific: the holder has already proved they have the code. */
    public static function notOpen(Invitation $invitation): self
    {
        $reason = match (true) {
            $invitation->accepted_at !== null => 'has already been accepted',
            $invitation->revoked_at !== null => 'was revoked',
            default => 'has expired',
        };

        return new self("That invitation {$reason}.");
    }

    public static function scopeNeedsSubject(Scope $scope): self
    {
        return new self(
            "An invitation at [{$scope->value}] scope must name the thing it grants access to."
        );
    }
}
