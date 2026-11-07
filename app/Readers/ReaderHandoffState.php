<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers;

/**
 * §12.4's `__Host-docup_state`: "PKCE verifier and return path during handoff".
 *
 * 🛑 **Not encrypted, and that is a considered position rather than an
 * oversight.** The documentation origin has no `EncryptCookies` middleware and
 * must not have one — §8.12.11 refuses a framework-encrypted grant because "a
 * Laravel-encrypted cookie can only be verified by PHP, foreclosing edge
 * authorisation", and adding the `web` group to `routes/docs.php` to encrypt
 * one cookie would bring a session, a CSRF token and Inertia to an origin whose
 * whole design is that none of them reach it.
 *
 * What protects the verifier is the cookie's own attributes: `__Host-`, so no
 * sibling subdomain can set or read it; `HttpOnly`, so documentation
 * JavaScript — which §14's threat model treats as attacker-controlled — cannot
 * read it; `Secure`, so it never crosses plaintext. An attacker who could read
 * it could read the session cookie beside it, so encryption would protect
 * nothing that is not already lost.
 *
 * 🛑 And the verifier is worth less than it looks: on its own it redeems
 * nothing. A code is needed too, and a code is minted only for a signed-in
 * dashboard user and dies in thirty seconds.
 */
final readonly class ReaderHandoffState
{
    private const int MAX_COOKIE_BYTES = 4096;

    public function __construct(
        public string $verifier,
        public string $returnPath,
        public int $attempt = 1,
    ) {}

    /**
     * The cookie value: base64url over compact JSON.
     *
     * base64url rather than raw JSON because a cookie value may not contain a
     * comma, a semicolon or whitespace, and a return path legitimately can.
     */
    public function toCookie(): string
    {
        return Grants\GrantKeys::base64Url((string) json_encode([
            'v' => $this->verifier,
            'r' => $this->returnPath,
            'n' => $this->attempt,
        ]));
    }

    /**
     * Parse a cookie value, or null when it is absent or unreadable.
     *
     * 🛑 Fails to null on **everything**, including a well-formed JSON object
     * with the wrong field types. The caller treats null as "no state", which
     * restarts the handoff — the correct outcome for a cookie somebody
     * tampered with, since tampering can only destroy a verifier they do not
     * have.
     */
    public static function fromCookie(mixed $raw): ?self
    {
        if (! is_string($raw) || $raw === '' || strlen($raw) > self::MAX_COOKIE_BYTES) {
            return null;
        }

        $json = base64_decode(strtr($raw, '-_', '+/'), true);

        if ($json === false) {
            return null;
        }

        try {
            $decoded = json_decode($json, true, 4, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return null;
        }

        if (! is_array($decoded)) {
            return null;
        }

        $verifier = $decoded['v'] ?? null;
        $return = $decoded['r'] ?? null;
        $attempt = $decoded['n'] ?? null;

        /*
         * 🛑 The verifier's shape is checked here, not at redemption. RFC 7636
         * fixes the unreserved-character set, and a verifier outside it cannot
         * have been produced by {@see PkceChallenge::create()} — so refusing it
         * now means the redemption path never hashes attacker-chosen bytes to
         * compare against a stored challenge.
         */
        if (! is_string($verifier) || preg_match('/^[A-Za-z0-9_-]{43,128}$/', $verifier) !== 1) {
            return null;
        }

        if (! is_string($return)) {
            return null;
        }

        // 🛑 `is_numeric` then cast, not `is_int` — Phase 20's finding.
        $n = is_numeric($attempt) ? (int) $attempt : 1;

        return new self(
            verifier: $verifier,
            returnPath: ReaderHandoff::safeReturnPath($return),
            attempt: max($n, 1),
        );
    }
}
