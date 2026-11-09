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

    /**
     * 🛑 A malformed entry in the CIDR binding.
     *
     * Refused at mint rather than stored, because an unparseable range matches
     * nothing and {@see ApiTokens::find()} fails closed — so the token
     * would be bound to the empty set and every request with it would 401 with
     * the same body as a stolen one. Safe, and undiagnosable.
     */
    public static function cidrInvalid(string $entry): self
    {
        return new self(
            '"'.$entry.'" is not an address or a CIDR range.'."\n\n"
            .'A token bound to an unparseable range is bound to nothing, and every request with '
            .'it would be refused with exactly the answer a stolen token gets — so this is '
            .'refused here, while you are still looking at the field.'
        );
    }

    public static function cidrTooMany(int $limit): self
    {
        return new self(
            'A token may be bound to at most '.$limit.' ranges. Every entry is compared on every '
            .'request this token makes; a list longer than that is a network boundary rather than '
            .'a credential binding, and belongs in the proxy.'
        );
    }

    /**
     * 🛑 Only the token's own holder may rotate it.
     *
     * Rotation returns a PLAINTEXT. Rotating somebody else's token would hand
     * the rotator a working credential belonging to another user — an
     * impersonation primitive, and one that would look in the audit chain like
     * the owner acting.
     */
    public static function notYours(): self
    {
        return new self(
            'Only the holder of a token may rotate it.'."\n\n"
            .'Rotation returns a new plaintext, so rotating another user\'s token would hand you '
            .'a credential that acts as them. Revoke it instead, which needs no secret.'
        );
    }

    /**
     * 🛑 An expired or revoked token cannot be rotated.
     *
     * Rotation exists to preserve continuity across a change of secret, and
     * there is no continuity to preserve once the old secret has stopped
     * working. Rotating a REVOKED token would be worse than useless: it would
     * resurrect a credential somebody deliberately turned off.
     */
    public static function notRotatable(): self
    {
        return new self(
            'Only a live token can be rotated.'."\n\n"
            .'Rotation carries a token\'s capabilities onto a new secret while the old one '
            .'finishes its life. A revoked token has no life to finish and was turned off on '
            .'purpose; an expired one has already stopped working. Mint a new token.'
        );
    }

    /**
     * 🛑 A token may be rotated once, so at most two secrets are live.
     *
     * Without this, rotating repeatedly leaves one family with three, four or
     * five working credentials and an operator with no idea how many are out
     * there — which is the state rotation exists to end.
     */
    public static function alreadyRotated(): self
    {
        return new self(
            'That token has already been rotated, and its successor is the live one.'."\n\n"
            .'A family holds at most two working secrets: rotating again would leave three, and '
            .'the point of rotation is to know how many are out there. Rotate the successor, or '
            .'revoke this one now if the overlap is no longer wanted.'
        );
    }

    /**
     * 🛑 An overlap window may only be SHORTENED.
     *
     * Extending the predecessor's expiry during a rotation is the opposite of
     * rotating: it prolongs the life of the secret being replaced, and it would
     * let a caller reach past §8.13.6's 365-day cap by rotating in a circle.
     */
    public static function overlapExtended(): self
    {
        return new self(
            'An overlap window can only end sooner than the old token already would.'."\n\n"
            .'Extending it would prolong the secret you are replacing, and rotating in a circle '
            .'would reach past the '.ApiTokens::MAXIMUM_LIFETIME_DAYS.'-day cap one window at a '
            .'time.'
        );
    }
}
