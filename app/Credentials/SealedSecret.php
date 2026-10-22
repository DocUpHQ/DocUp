<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Credentials;

/**
 * One envelope: a payload sealed under a per-record data key, and that data
 * key sealed under the installation's KEK (§9.1.7).
 *
 * 🛑 The two halves are stored in separate columns on purpose. Rotating the
 * KEK then rewrites **only** `wrappedKey` — 60 bytes per credential — and
 * never touches, decrypts or even reads the payload. That is what makes
 * §9.1.7's "`installation_security_admin` may rotate but never read"
 * implementable rather than aspirational: the rotation path has no code that
 * could produce plaintext, so the capability is absent rather than merely
 * unexercised.
 *
 * `kekFingerprint` says which KEK wrapped this record without storing
 * anything that helps unwrap it, so a rotation can find the records it has
 * not yet reached and a decrypt can skip keys that cannot be right.
 */
final readonly class SealedSecret
{
    public function __construct(
        public int $version,
        public string $kekFingerprint,
        public string $wrappedKey,
        public string $ciphertext,
    ) {}
}
