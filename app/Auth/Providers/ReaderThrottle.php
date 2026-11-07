<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers;

use Illuminate\Support\Facades\RateLimiter;

/**
 * 🛑 §8.12.16's last sentence: "Share-link password attempts MUST be
 * rate-limited with lockout and timing-safe comparison."
 *
 * One limiter for every reader credential attempt, not just the share link's,
 * because the requirement's reason applies to all of them: a `password` binding
 * and a passworded share link are both a short secret somebody will guess at,
 * and a bearer token is a long one somebody will spray.
 *
 * ## 🛑 Why the key is the credential and not the address
 *
 * Keying on the IP alone is the obvious design and it is wrong in both
 * directions. A corporate NAT puts a thousand legitimate readers behind one
 * address, so an IP limiter locks out a company because one person fat-fingered
 * a password; and an attacker with a /64 of IPv6 has effectively unlimited
 * attempts against one link.
 *
 * So there are **two** limiters and a failure trips both:
 *
 * - per **credential**, which bounds how fast one link's password can be
 *   guessed no matter where from;
 * - per **credential and address**, much tighter, which stops one client
 *   burning the shared budget for everybody else.
 *
 * A reader behind the NAT who types their password correctly is never
 * throttled, because only failures count.
 */
final readonly class ReaderThrottle
{
    /**
     * Failures per credential before the lockout, and for how long.
     *
     * 🛑 Twenty in fifteen minutes. The number is a trade-off stated rather
     * than guessed: a share-link password is typically a word an operator sent
     * in an email, so the realistic attack is a dictionary and the realistic
     * legitimate failure is a typo or a stale link in a bookmark. Twenty
     * tolerates a confused team; fifteen minutes makes a 10,000-word dictionary
     * take fifty hours.
     */
    private const int CREDENTIAL_ATTEMPTS = 20;

    private const int CREDENTIAL_WINDOW = 900;

    /**
     * And per credential **and** address — much tighter, because a single
     * client has no legitimate reason to fail five times.
     */
    private const int CLIENT_ATTEMPTS = 5;

    private const int CLIENT_WINDOW = 900;

    /**
     * Whether this attempt is allowed to proceed.
     *
     * 🛑 Checked **before** the comparison, so a locked-out client's guess is
     * never compared at all. Checking afterwards would leak through timing the
     * very thing the lockout exists to protect.
     *
     * @param  string  $credentialKey  an opaque, stable identifier for the
     *                                 credential — 🛑 never the secret itself,
     *                                 which would put it in a cache key
     */
    public function permits(string $credentialKey, ?string $address): bool
    {
        if (RateLimiter::tooManyAttempts($this->credentialKey($credentialKey), self::CREDENTIAL_ATTEMPTS)) {
            return false;
        }

        if ($address === null) {
            return true;
        }

        return ! RateLimiter::tooManyAttempts(
            $this->clientKey($credentialKey, $address),
            self::CLIENT_ATTEMPTS,
        );
    }

    /**
     * Record a failure against both limiters.
     *
     * 🛑 **Only failures are counted.** A limiter that counted successes would
     * throttle a popular share link — which is the one thing a share link is
     * for — and the operator's fix would be to turn the limiter off.
     */
    public function fail(string $credentialKey, ?string $address): void
    {
        RateLimiter::hit($this->credentialKey($credentialKey), self::CREDENTIAL_WINDOW);

        if ($address !== null) {
            RateLimiter::hit($this->clientKey($credentialKey, $address), self::CLIENT_WINDOW);
        }
    }

    /**
     * Clear both limiters after a success.
     *
     * 🛑 So a reader who mistyped twice and then succeeded does not carry two
     * failures into their next visit. Without this, a team sharing one link
     * accumulates a lockout over a week of ordinary typos.
     */
    public function succeed(string $credentialKey, ?string $address): void
    {
        RateLimiter::clear($this->credentialKey($credentialKey));

        if ($address !== null) {
            RateLimiter::clear($this->clientKey($credentialKey, $address));
        }
    }

    /**
     * Seconds until this client may try again, for the operator-facing log.
     *
     * 🛑 **Not for the reader.** §8.12.23 forbids the response varying with
     * what the client sent, and a `Retry-After` that appeared only for a
     * locked-out client would confirm that the credential they are guessing at
     * exists.
     */
    public function secondsUntilRetry(string $credentialKey, ?string $address): int
    {
        $longest = RateLimiter::availableIn($this->credentialKey($credentialKey));

        if ($address !== null) {
            $longest = max($longest, RateLimiter::availableIn($this->clientKey($credentialKey, $address)));
        }

        return max($longest, 0);
    }

    /**
     * 🛑 Hashed, so the cache key cannot be read back into a credential id.
     *
     * The limiter's store is Valkey, which §11 shares with the queue and the
     * cache; a key naming a credential id would put a list of every share link
     * that has ever been guessed at into a store with a different threat model
     * from the database's.
     */
    private function credentialKey(string $credentialKey): string
    {
        return 'reader-credential:'.hash('sha256', $credentialKey);
    }

    private function clientKey(string $credentialKey, string $address): string
    {
        return 'reader-credential-client:'.hash('sha256', $credentialKey.'|'.$address);
    }
}
