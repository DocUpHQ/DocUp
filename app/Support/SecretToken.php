<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Support;

/**
 * Generation, hashing and lookup of §9.1.4 security tokens.
 *
 * 🛑 §9.1.4 governs every enumerable secret in DocUp — invitation codes, API
 * tokens, share tokens, webhook secrets, domain-verification tokens: **32
 * CSPRNG bytes, stored as a SHA-256 hash, and never UUIDv7.** The v7
 * prohibition is the part worth understanding: v7 embeds a readable
 * millisecond timestamp, so a v7 invitation code would narrow a brute-force
 * search to the moment the invitation was sent. UUIDv7 is correct for entity
 * keys precisely because it leaks creation time, which is exactly why it is
 * wrong here.
 *
 * One class for all of them, so the next secret added gets the same treatment
 * by construction rather than by whoever writes it remembering §9.1.4 exists.
 *
 * On the stored prefix: §8.13.6 wants an indexed prefix so a lookup finds its
 * candidate row without scanning the table. The prefix is taken from the
 * **hash**, not from the token, so the index reveals nothing a stolen database
 * did not already reveal — a prefix of the plaintext would hand an attacker
 * the first bytes of every live credential.
 */
final class SecretToken
{
    /** §9.1.4: 32 CSPRNG bytes. */
    private const BYTES = 32;

    /**
     * Hex characters of the hash kept for indexed lookup.
     *
     * 12 hex characters is 48 bits: ample to make collisions a non-event at any
     * plausible number of live tokens, while the comparison still happens on
     * the full hash. The column is VARCHAR(12), so changing this needs a
     * migration.
     */
    private const PREFIX_LENGTH = 12;

    /**
     * A fresh token in its presentation form.
     *
     * URL-safe base64 without padding: these are pasted into terminals, CI
     * variables and `Authorization` headers, and `+`, `/` and `=` each get
     * mangled by something along that path.
     *
     * @param  string  $prefix  a human-readable marker, e.g. `docup_pat`. Not a
     *                          secret, and deliberately visible: a leaked token
     *                          in a log or a public repository is identifiable
     *                          as DocUp's, which is what lets secret scanners
     *                          report it instead of ignoring it.
     */
    public static function generate(string $prefix = 'docup'): string
    {
        $random = rtrim(strtr(base64_encode(random_bytes(self::BYTES)), '+/', '-_'), '=');

        return $prefix.'_'.$random;
    }

    /** The SHA-256 hash to store. Never store or log the token itself. */
    public static function hash(string $token): string
    {
        return hash('sha256', $token);
    }

    /** The indexed lookup prefix, derived from the hash rather than the token. */
    public static function prefix(string $token): string
    {
        return substr(self::hash($token), 0, self::PREFIX_LENGTH);
    }

    /**
     * Constant-time comparison of a presented token against a stored hash.
     *
     * `hash_equals`, not `===`: comparing a credential is where timing analysis
     * belongs even when the attacker is assumed not to be measuring, because
     * the habit is what survives into the code where they are.
     */
    public static function matches(string $presented, string $storedHash): bool
    {
        return hash_equals($storedHash, self::hash($presented));
    }
}
