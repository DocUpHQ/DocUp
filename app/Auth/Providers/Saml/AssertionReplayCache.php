<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Saml;

use Illuminate\Support\Facades\Cache;

/**
 * 🛑 §8.12.18's "assertion-id replay cache".
 *
 * A SAML assertion is a bearer credential that travels **through the browser**,
 * which is the whole problem: it reaches the reader's machine, their proxy,
 * their extensions and their history, and it stays valid until its
 * `NotOnOrAfter`. The only thing that makes a captured assertion worthless is
 * remembering that it has already been used.
 *
 * ## 🛑 Why this is `Cache::add` and not a table
 *
 * Phase 24's `oidc_authorisation_requests` is a table because DocUp *writes* an
 * authorisation request before the reader leaves, and the row carries state the
 * callback needs. A replay cache carries nothing: it answers one boolean, it is
 * written once per login, and every entry expires on its own.
 *
 * `Cache::add()` is an **atomic** set-if-absent — the same latch
 * `JwksStore`'s refresh floor uses — so two concurrent presentations of one
 * assertion cannot both win. A `has()` then `put()` would be the race this
 * class exists to close, and a table would need the same conditional write plus
 * a sweep nobody would schedule.
 *
 * §11.2 makes Valkey "**Mandatory, not optional** — atomic locks, caches,
 * Horizon, the epoch feed and the TLS allowlist all depend on it", so the
 * atomicity is a property of the deployment rather than a hope.
 *
 * 🛑 **And a cache miss is fail-closed.** If the cache is unreachable,
 * {@see self::remember()} raises rather than letting the login through: an
 * installation whose Valkey is down must stop accepting assertions, not stop
 * checking them. That is the opposite of how a cache usually fails, and it is
 * why this class exists instead of a `Cache::add` call at the call site.
 */
final readonly class AssertionReplayCache
{
    /**
     * 🛑 The floor on how long an id is remembered, in seconds.
     *
     * An identity provider that issues an assertion with a very short window
     * would otherwise have its ids forgotten almost immediately — and a replay
     * arriving inside DocUp's own ±120-second skew would then be accepted. So
     * the remembered lifetime is never shorter than twice the skew, whatever
     * the assertion said.
     */
    public const int MINIMUM_SECONDS = 2 * ResponseValidator::MAX_SKEW_SECONDS;

    /**
     * 🛑 And a ceiling, because an assertion with a year-long window would
     * otherwise pin an entry for a year.
     *
     * Twelve hours is longer than any sane assertion lifetime and short enough
     * that a misconfigured provider cannot fill the cache indefinitely. An
     * assertion still valid after that is one whose own window DocUp should be
     * refusing on §8.12.18's grounds rather than remembering.
     */
    public const int MAXIMUM_SECONDS = 12 * 3600;

    /**
     * Remember this assertion id, or refuse it as a replay.
     *
     * 🛑 The **certificate** is part of the key, not only the id. Assertion ids
     * are chosen by the identity provider and are only unique within it, so two
     * providers can legitimately issue the same id — and a global key would let
     * one provider's traffic refuse another's. Keying on the certificate scopes
     * the cache to the issuer that actually signed it, which is narrower than
     * keying on the binding: a binding whose certificate is rotated starts a
     * fresh namespace, which is correct, because assertions signed by the old
     * key are no longer acceptable anyway.
     *
     * @param  string  $id  the assertion's `ID`
     * @param  string  $certificate  PEM, from the binding
     * @param  int  $until  unix seconds; when the id may be forgotten
     *
     * @throws SamlRefused
     */
    public function remember(string $id, string $certificate, int $until): void
    {
        $ttl = max(
            self::MINIMUM_SECONDS,
            min(self::MAXIMUM_SECONDS, $until - time()),
        );

        try {
            /*
             * 🛑 `add` returns false when the key already exists, atomically.
             * That false **is** the replay — there is no read before it and no
             * window between the check and the write.
             */
            $won = Cache::add($this->key($id, $certificate), 1, $ttl);
        } catch (\Throwable $e) {
            /*
             * 🛑 Fail **closed**. A cache that cannot answer has not said the
             * assertion is fresh, and §8.12.18 requires the check rather than
             * an attempt at it. An installation whose Valkey is down should
             * stop accepting SAML logins — loudly, with this in the audit chain
             * — rather than accept every replay for the duration.
             */
            throw SamlRefused::of(
                SamlRejection::AssertionReplayed,
                'the replay cache is unavailable, so freshness cannot be established',
            );
        }

        if ($won !== true) {
            throw SamlRefused::of(
                SamlRejection::AssertionReplayed,
                'this assertion has already been presented',
            );
        }
    }

    /**
     * Whether this id would be refused, without consuming it.
     *
     * 🛑 For a test and for `docup:doctor`, never for the serving path — a
     * caller that asked this and then called {@see self::remember()} would have
     * reintroduced the race. Named so that reading the call site makes the
     * mistake obvious.
     */
    public function wouldRefuse(string $id, string $certificate): bool
    {
        return Cache::has($this->key($id, $certificate));
    }

    /**
     * 🛑 The id is **hashed**, not stored.
     *
     * A cache key is readable by anybody with Valkey access, and an assertion
     * id is a token an identity provider chose — occasionally a value with
     * structure in it. §20.3's argument about raw identifiers applies: nothing
     * is lost by hashing and a readable key is a disclosure nobody chose.
     *
     * Keyed with the application key for the reason
     * `App\Access\DecisionLog::subjectHash()` gives: an unkeyed digest of
     * a small domain is reversible by enumeration.
     */
    private function key(string $id, string $certificate): string
    {
        $appKey = config('app.key');

        return 'saml:replay:'.hash_hmac(
            'sha256',
            $certificate."\0".$id,
            is_string($appKey) ? $appKey : '',
        );
    }
}
