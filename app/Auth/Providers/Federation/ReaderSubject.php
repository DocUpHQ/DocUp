<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Federation;

use App\Access\DecisionLog;

/**
 * 🛑 §8.12.1's `subject_hash`: a provider's `sub`, keyed so the column cannot
 * hold a readable subject.
 *
 * > "Reader identities MUST be keyed `(binding_id, subject_hash)`, **email MUST
 * > NEVER be used for linking or lookup**."
 *
 * ## Why keyed rather than plainly hashed
 *
 * The same argument {@see DecisionLog::subjectHash()} makes: "an
 * unkeyed digest of a small domain … is reversible by enumeration". An OIDC
 * `sub` is *often* an opaque UUID, which is not a small domain — but it is
 * provider-assigned and some providers use the username or the email address,
 * which is. A plain digest would let anybody with a copy of the database
 * confirm "this person reads that project" by computing one hash, which is
 * precisely the disclosure §8.12.1 is built to prevent.
 *
 * ## 🛑 And why the binding is in the digest
 *
 * The unique key is `(binding_id, subject_hash)`, so the binding is already a
 * dimension of the row — mixing it into the digest too looks redundant. It is
 * not: without it, the same `sub` at two different providers digests
 * identically, so a join across two organisations' identity tables would reveal
 * that one person reads both. The column is per-organisation data; the digest
 * should not be a cross-organisation correlator.
 *
 * ## 🛑 Key rotation, and what it costs
 *
 * `APP_KEY` can rotate (§9.1.7, §15.2), and a keyed digest changes when it
 * does. So {@see self::candidates()} returns a digest under the current key
 * **and** under each `APP_PREVIOUS_KEYS` entry, and a lookup tries all of them
 * — the same shape `EnvelopeCipher::open()` uses, which "tries every candidate
 * KEK".
 *
 * A caller that finds an identity under a previous key re-keys the row to the
 * current one, so the set shrinks back to one over time. Without that, an
 * installation that had rotated twice would carry the cost for ever; with it,
 * rotation is self-healing and an operator who drops a previous key from the
 * configuration only orphans readers who have not logged in since.
 */
final readonly class ReaderSubject
{
    /**
     * The digest to **write**, under the current key.
     *
     * @param  string  $bindingId  raw 16 bytes
     * @return string raw 32 bytes, for the `BINARY(32)` column
     */
    public static function hash(string $bindingId, string $subject): string
    {
        return self::digest($bindingId, $subject, self::currentKey());
    }

    /**
     * Every digest to **look up** by: the current key first, then each previous
     * one.
     *
     * 🛑 Current first and the order preserved, so a caller can tell a hit
     * under the current key (nothing to do) from a hit under an older one
     * (re-key the row). The first element is always {@see self::hash()}'s
     * output.
     *
     * @param  string  $bindingId  raw 16 bytes
     * @return list<string> raw 32-byte digests, at least one
     */
    public static function candidates(string $bindingId, string $subject): array
    {
        $digests = [self::digest($bindingId, $subject, self::currentKey())];

        foreach (self::previousKeys() as $key) {
            $digest = self::digest($bindingId, $subject, $key);

            if (! in_array($digest, $digests, true)) {
                $digests[] = $digest;
            }
        }

        return $digests;
    }

    /**
     * 🛑 A display label that is **not** an email address.
     *
     * §8.12.1 forbids email "for linking or lookup", and the schema's own
     * comment goes further: "a column present for display is one `WHERE` away
     * from being used for lookup". So the label is a name where the provider
     * sent one, and otherwise a short digest fragment — never the email, even
     * when it is the only human-readable claim available.
     *
     * An operator looking at a session inventory needs to tell two readers
     * apart, which a digest fragment does. They do not need to know who those
     * readers are; if they do, that is the identity provider's directory.
     *
     * @param  array<string, mixed>  $claims
     */
    public static function displayLabel(array $claims, string $subjectHash): string
    {
        foreach (['name', 'preferred_username', 'given_name'] as $claim) {
            $value = $claims[$claim] ?? null;

            if (is_string($value) && $value !== '' && ! str_contains($value, '@')) {
                /*
                 * 🛑 The `@` test is not an email validator; it is a refusal to
                 * store a value that looks like one. A provider that puts the
                 * email in `preferred_username` — Entra does — would otherwise
                 * put it in this column by a route nobody chose.
                 */
                return mb_substr($value, 0, 120);
            }
        }

        return 'reader-'.substr(bin2hex($subjectHash), 0, 12);
    }

    private static function digest(string $bindingId, string $subject, string $key): string
    {
        /*
         * 🛑 The binding is length-prefixed by being fixed-width 16 bytes, so
         * there is no concatenation ambiguity: no two (binding, subject) pairs
         * can produce the same input string. A separator alone would not be
         * enough if a subject could contain it.
         */
        return hash_hmac('sha256', $bindingId.$subject, $key, binary: true);
    }

    private static function currentKey(): string
    {
        $key = config('app.key');

        return is_string($key) ? $key : '';
    }

    /** @return list<string> */
    private static function previousKeys(): array
    {
        $configured = config('app.previous_keys', []);
        $keys = [];

        foreach (is_array($configured) ? $configured : [] as $key) {
            if (is_string($key) && $key !== '') {
                $keys[] = $key;
            }
        }

        return $keys;
    }
}
