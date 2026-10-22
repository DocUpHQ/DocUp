<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Exceptions;

use App\Auth\ApiTokens;
use App\Auth\Capability;

/**
 * A token could not be minted (§8.13.6).
 *
 * These are for the person minting, who is authenticated and acting
 * deliberately, so they are specific and say what to do instead.
 *
 * 🛑 None of this is ever shown to a token bearer. A failed authentication gets
 * one generic answer, because distinguishing "expired" from "revoked" from
 * "never existed" tells an attacker which of their stolen tokens is worth more
 * effort — which is why {@see ApiTokens::find()} returns null rather than
 * throwing any of these.
 */
final class TokenRejected extends \RuntimeException
{
    public static function noCapabilities(): self
    {
        return new self(
            'A token must grant at least one capability. One granting nothing is a credential '
            .'that can only ever fail, and it will be debugged as a bug rather than recognised '
            .'as a mistake at mint time.'
        );
    }

    public static function installationAdministrative(Capability $capability): self
    {
        return new self(
            '🛑 §8.13.6: no token may hold installation-scope administrative capability, and '
            ."[{$capability->value}] is one.\n\n"
            .'Checked at mint rather than at use because such a token is dangerous the moment it '
            .'exists: it only has to leak once. Administrative actions need an interactive '
            .'session with step-up re-authentication (§8.13.5).'
        );
    }

    public static function exceedsMinter(Capability $capability): self
    {
        return new self(
            "You cannot mint a token holding [{$capability->value}] because you do not hold it "
            ."yourself.\n\nOtherwise minting is an escalation primitive: grant a token more than "
            .'you have, then act as the token.'
        );
    }

    public static function expiryInThePast(): self
    {
        return new self('A token cannot expire in the past.');
    }

    public static function expiryTooFar(): self
    {
        return new self(
            'Token lifetime is capped at '.ApiTokens::MAXIMUM_LIFETIME_DAYS.' days (§8.13.6). '
            .'Use overlap rotation for continuity rather than a longer life: a credential nobody '
            .'has had to re-examine for a year is one nobody knows the scope of.'
        );
    }
}
