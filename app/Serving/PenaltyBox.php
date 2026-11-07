<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

use Illuminate\Support\Facades\Cache;

/**
 * 🛑 §8.11.8's progressive penalty box for 404 bursts and search.
 *
 * > "404 responses MUST be edge-cacheable with a short TTL, and a
 * > progressive per-source penalty-box limiter MUST apply to 404 bursts and
 * > search. Read the Docs' June 2026 DDoS targeted exactly these paths."
 *
 * **The two halves of that sentence pull in opposite directions and both
 * are required**, which is the whole design problem:
 *
 *  - *Edge-cacheable* means the edge answers a repeat 404 without asking
 *    the application. That is what makes a flood of the **same** URL free.
 *  - *Rate-limited* means the application answers fewer of them. That is
 *    what makes a flood of **distinct** URLs survivable — and distinct URLs
 *    are what an attacker sends, precisely because they miss every cache.
 *
 * Read the Docs' June 2026 incident is the reference, and it is in the
 * requirement because the pattern is not hypothetical.
 *
 * 🛑 **Progressive**, not a flat limit: the penalty grows with repetition,
 * so an ordinary reader with a stale bookmark is never affected and a
 * source generating thousands is held off for longer each time. A flat
 * limit has to be set either high enough to be useless or low enough to
 * catch a crawler.
 *
 * 🛑 **Counting does not make the response private.** The limiter writes to
 * Valkey; the 404 it is counting still carries a public, short cache
 * directive, because §8.11.8 asks for both at once. A limiter that
 * suppressed caching would hand an attacker the thing they wanted — every
 * request reaching the origin — as a side effect of the defence.
 */
final readonly class PenaltyBox
{
    /** Generous for a human with stale bookmarks, nothing for a scanner. */
    public const int FREE_PER_MINUTE = 60;

    /** How long the first penalty lasts; it doubles from there. */
    public const int FIRST_PENALTY_SECONDS = 60;

    /** An hour. Longer serves nobody: the source will be back. */
    public const int MAX_PENALTY_SECONDS = 3600;

    /** How long a source's record of past penalties survives without one. */
    public const int MEMORY_SECONDS = 86400;

    private const PREFIX = 'serving:penalty:';

    /**
     * Whether this source is currently held off.
     *
     * 🛑 One cache read on the hot path, and it happens **after** the
     * response has been decided, never before: a penalty box that gated
     * resolution would add a cache round trip to every ordinary request to
     * protect against a case that is rare. It gates the *answer*, not the
     * work.
     */
    public function isPenalised(string $source): bool
    {
        return self::number(Cache::get(self::PREFIX.'until:'.self::key($source))) !== null;
    }

    /**
     * Record a 404 or a search from this source, and return whether the
     * source has just crossed into a penalty.
     */
    public function record(string $source): bool
    {
        $key = self::key($source);

        $count = self::number(Cache::increment(self::PREFIX.'count:'.$key));

        if ($count === null) {
            /*
             * The counter did not exist. `increment` on a missing key is
             * driver-dependent — Redis creates it at 1, the array store
             * returns false — so the first hit is written explicitly, with
             * the window's own TTL.
             */
            Cache::put(self::PREFIX.'count:'.$key, 1, 60);

            return false;
        }

        if ($count === 1) {
            Cache::put(self::PREFIX.'count:'.$key, 1, 60);
        }

        if ($count <= self::FREE_PER_MINUTE) {
            return false;
        }

        $this->penalise($key);

        return true;
    }

    /** How long the current penalty has left, in seconds, or null. */
    public function secondsRemaining(string $source): ?int
    {
        $until = self::number(Cache::get(self::PREFIX.'until:'.self::key($source)));

        if ($until === null) {
            return null;
        }

        $left = $until - time();

        return $left > 0 ? $left : null;
    }

    /**
     * 🛑 A number out of the cache, whatever the driver made of it.
     *
     * **This is not defensive padding; it is the only correct way to read
     * a cache.** Redis stores strings and returns strings; the array store
     * returns whatever it was given. An earlier draft of this class used
     * `is_int()`, which is true on the array store and false on Redis — so
     * every assertion passed under `CACHE_STORE=array` and the penalty box
     * never engaged in production, where the store is Redis. The symptom
     * would have been a limiter that counted correctly, reported
     * `isPenalised` correctly, and had no effect.
     *
     * Found by a test that happened to run against Redis. Nothing else
     * would have found it.
     */
    private static function number(mixed $value): ?int
    {
        return is_numeric($value) ? (int) $value : null;
    }

    /**
     * 🛑 Doubling, and the previous level is remembered for a day.
     *
     * Without the memory the progression resets the moment a penalty
     * lapses, so a source that waits sixty seconds between bursts is never
     * penalised for more than sixty seconds — which is the whole attack,
     * with a timer.
     */
    private function penalise(string $key): void
    {
        $previous = self::number(Cache::get(self::PREFIX.'level:'.$key));
        $level = $previous === null ? 1 : $previous + 1;

        $seconds = (int) min(
            self::MAX_PENALTY_SECONDS,
            self::FIRST_PENALTY_SECONDS * (2 ** ($level - 1)),
        );

        Cache::put(self::PREFIX.'level:'.$key, $level, self::MEMORY_SECONDS);
        Cache::put(self::PREFIX.'until:'.$key, time() + $seconds, $seconds);
    }

    /**
     * 🛑 The source is hashed before it becomes a cache key.
     *
     * §20.3 gives a raw IP a **7-day** retention and calls it "the only
     * place a raw IP exists"; a cache key is not that place. A salted hash
     * identifies a source across requests without storing who they are,
     * which is all a limiter needs.
     */
    private static function key(string $source): string
    {
        $salt = config('app.key');

        return hash('sha256', $source.'|'.(is_string($salt) ? $salt : ''));
    }
}
