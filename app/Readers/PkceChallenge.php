<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers;

use App\Readers\Grants\GrantKeys;
use App\Support\SecretToken;

/**
 * §8.12.10's PKCE pair, `S256` only.
 *
 * ## 🛑 What PKCE is actually buying here
 *
 * This is not an OAuth exchange with a third party, so it is worth being
 * precise about the attack it closes. §8.12.10's handoff code travels to the
 * documentation origin **in a URL**, which means it reaches the browser's
 * history, the `Referer` of anything the landing page loads, and any proxy log
 * between the two. Without PKCE, possession of that URL is possession of a
 * session.
 *
 * With it, redemption needs the verifier as well, and the verifier only ever
 * exists in a `__Host-`, `HttpOnly`, `Secure` cookie on the origin that started
 * the handoff. So a leaked code is redeemable only by the browser that asked
 * for it — which is exactly the property RFC 7636 describes and the reason
 * §8.12.18 makes `S256` mandatory rather than optional for the OIDC driver that
 * will follow this one.
 *
 * 🛑 **No `plain` method.** RFC 7636 permits it; this does not. A `plain`
 * challenge is the verifier, so a code and its challenge travelling together
 * prove nothing at all, and supporting both would mean the method itself
 * becomes a parameter an attacker chooses.
 */
final readonly class PkceChallenge
{
    /**
     * The verifier's length in bytes before base64url encoding.
     *
     * 32 bytes is 43 base64url characters, which is RFC 7636's minimum of 43
     * exactly and the length a 32-byte digest encodes to — so the challenge and
     * the verifier are the same width and a transposition of the two cannot be
     * hidden by a length check that passes.
     */
    private const int VERIFIER_BYTES = 32;

    private function __construct(
        public string $verifier,
        public string $challenge,
    ) {}

    /** A fresh pair. */
    public static function create(): self
    {
        $verifier = GrantKeys::base64Url(random_bytes(self::VERIFIER_BYTES));

        return new self($verifier, self::challengeFor($verifier));
    }

    /**
     * 🛑 `S256`: base64url(SHA-256(ASCII(verifier))), per RFC 7636 §4.2.
     *
     * The digest is over the **encoded** verifier, not the raw bytes behind it.
     * That is what the RFC says and what every other implementation does, and
     * getting it wrong produces a system that works perfectly against itself
     * and fails against the OIDC provider P24 points at the same code.
     */
    public static function challengeFor(string $verifier): string
    {
        return GrantKeys::base64Url(hash('sha256', $verifier, binary: true));
    }

    /**
     * Whether a presented verifier satisfies a stored challenge.
     *
     * 🛑 `hash_equals`, for the reason {@see SecretToken::matches()}
     * gives: this is a credential comparison, and the habit is what survives
     * into the code where timing is measurable.
     */
    public static function satisfies(string $verifier, string $challenge): bool
    {
        return hash_equals($challenge, self::challengeFor($verifier));
    }
}
