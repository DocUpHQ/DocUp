<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls\Acme;

use Illuminate\Support\Facades\Cache;

/**
 * The `http-01` responses this installation is currently prepared to serve
 * (RFC 8555 §8.3, §8.10.18).
 *
 * 🛑 **The cache, not the database, and the reason is the lifetime.** A
 * challenge is answered once, within seconds, by one CA, and is then
 * worthless. A table would need a purge job to stop accumulating rows whose
 * only property is that they are no longer valid — and §20.3 says one purge
 * job, one retention table. A short TTL in Valkey expresses "this is live
 * for the next five minutes" in the one place that already means it.
 *
 * 🛑 The token is the CA's, not ours: it arrives in the challenge object and
 * is used as a cache key, so it is normalised to the base64url alphabet
 * before it reaches `Cache` — an unvalidated key from a remote party is how
 * a cache gets a key injected into it.
 */
final class AcmeChallenges
{
    /**
     * Long enough for a CA that queues validations, short enough that a
     * token which never gets validated disappears on its own. Let's Encrypt
     * validates in seconds; step-ca is immediate.
     */
    public const int TTL_SECONDS = 300;

    private const PREFIX = 'tls:acme-challenge:';

    public function publish(string $token, string $keyAuthorization): void
    {
        Cache::put(self::key($token), $keyAuthorization, self::TTL_SECONDS);
    }

    public function answer(string $token): ?string
    {
        $value = Cache::get(self::key($token));

        return is_string($value) ? $value : null;
    }

    public function withdraw(string $token): void
    {
        Cache::forget(self::key($token));
    }

    /**
     * 🛑 A token that is not base64url cannot be one a CA issued, and must
     * never reach the cache driver as part of a key. Returning a constant
     * unreachable key rather than throwing keeps the serving path (which
     * looks up whatever is in the URL) free of exceptions for ordinary
     * garbage — a 404 is the right answer to a nonsense token.
     */
    private static function key(string $token): string
    {
        if (preg_match('/\A[A-Za-z0-9_-]{1,255}\z/', $token) !== 1) {
            return self::PREFIX.'invalid';
        }

        return self::PREFIX.$token;
    }
}
