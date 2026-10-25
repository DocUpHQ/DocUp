<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Webhooks;

/**
 * §11.1's "one shared raw-body verifier".
 *
 * 🛑 **Raw** body, and the word is load-bearing. §8.19.3 requires the HMAC
 * over the bytes the provider signed, and `json_decode` followed by
 * `json_encode` is not those bytes: key order, unicode escaping, float
 * formatting and whitespace all change. A verifier handed a re-encoded body
 * either rejects every genuine delivery or — worse, if someone "fixes" it by
 * normalising both sides — accepts a forgery that normalises to the same
 * thing.
 *
 * 🛑 **Constant-time comparison**, per §8.19.3. `===` on a hex digest leaks
 * the length of the matching prefix through timing, and an attacker who can
 * send unlimited deliveries can recover a valid signature byte by byte. There
 * is no version of this comparison that may use `==`, `===`, `strcmp` or
 * `substr_compare`.
 *
 * One class, one method, no state: it exists so that four schemes cannot
 * each grow their own comparison, and so an architecture test can assert that
 * nothing else in the application calls `hash_hmac` for a webhook.
 */
final readonly class RawBodyVerifier
{
    /**
     * Compare a presented signature against HMAC-SHA256 over the payload.
     *
     * @param  string  $signedPayload  exactly the bytes the provider signed
     * @param  string  $secret  the shared secret, already unsealed
     * @param  string  $presented  the signature as the provider sent it, decoded
     * @param  SignatureEncoding  $encoding  how the provider spells the digest
     */
    public function matches(
        string $signedPayload,
        string $secret,
        string $presented,
        SignatureEncoding $encoding,
    ): bool {
        $expected = $encoding->encode(hash_hmac('sha256', $signedPayload, $secret, true));

        /*
         * 🛑 `hash_equals` is length-safe as well as content-safe, so a
         * presented value of the wrong length returns false without
         * revealing where it stopped matching. A length check before the
         * comparison would reintroduce exactly the oracle this avoids.
         */
        return hash_equals($expected, $presented);
    }

    /**
     * Compare two opaque secrets in constant time.
     *
     * For {@see SignatureScheme::SharedToken}, where the provider sends the
     * secret itself rather than a signature over anything. Separate from
     * {@see matches()} so that the one scheme with no HMAC cannot be reached
     * by a caller that meant to verify a signature and passed the wrong
     * arguments.
     */
    public function secretMatches(string $expected, string $presented): bool
    {
        return hash_equals($expected, $presented);
    }
}
