<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers;

use App\Models\DocsSession;
use App\Readers\Grants\GrantMinter;
use App\Readers\Grants\GrantVerifier;
use Symfony\Component\HttpFoundation\Cookie;

/**
 * 🛑 §12.4's cookie table, as the one place it is written.
 *
 * > "Every cookie is `__Host-` prefixed, Secure, HttpOnly, `SameSite=Lax`. 🛑
 * > The `__Host-` prefix requires `Secure`, **no** `Domain` attribute and
 * > **`Path=/`** — a browser silently rejects a `__Host-` cookie with any other
 * > path — so none of these five may be path-scoped, and all of them therefore
 * > ride on every request to their origin. `__Secure-` is **not** an acceptable
 * > substitute for the two that would otherwise want a path: it permits a
 * > `Domain` attribute, which would defeat this table's own rule and §14.1/2's
 * > containment argument. No cookie is ever set on a parent domain."
 *
 * 🛑 **One factory, because the failure mode is silence.** A `__Host-` cookie
 * with a `Domain` attribute or a path other than `/` is not rejected loudly —
 * the browser simply does not store it, the next request arrives with no
 * session, and the reader loops through the handoff forever. There is no server
 * error and nothing in a log. So the attributes are not parameters: every
 * cookie this class makes gets them, and {@see self::attributes()} exists for
 * the test that asserts it.
 *
 * 🛑 **None of these is ever encrypted by the framework**, and that is §8.12.11
 * refusing a symmetric design:
 *
 * > "a Laravel-encrypted cookie can only be verified by PHP, foreclosing edge
 * > authorisation."
 *
 * Structurally true rather than configured: `routes/docs.php` has no `web`
 * middleware group, so `EncryptCookies` never runs on a documentation origin.
 * An architecture test asserts the names are absent from the encrypter's
 * exception list, because adding them there would be the one change that makes
 * this comment false without changing this file.
 */
final readonly class ReaderCookies
{
    /** §12.4: "opaque handle to a server-side revocable `docs_sessions` row". */
    public const string SESSION = '__Host-docup_rsess';

    /** §12.4: "Ed25519 grant, the per-request bearer; the edge verifies, never mints". */
    public const string GRANT = '__Host-docup_grant';

    /** §12.4: "opaque cache key for Tier B; carries no session material". */
    public const string CACHE_KEY = '__Host-docup_ck';

    /** §12.4: "PKCE verifier and return path during handoff". */
    public const string STATE = '__Host-docup_state';

    /**
     * §12.4's dashboard cookie, named here only so the table is complete and
     * testable in one place.
     *
     * 🛑 This class never **makes** it: it is Laravel's session cookie,
     * configured in `config/session.php`, on a different origin. Naming it
     * without owning it is the point — §12.4 is five rows, and a table that
     * listed four would read as if the fifth had no rule.
     */
    public const string DASHBOARD = '__Host-docup_session';

    /** §12.4's "5 m" for the handoff state. */
    public const int STATE_TTL_SECONDS = 300;

    /**
     * The session handle's own cookie lifetime, in minutes.
     *
     * 🛑 Set from §12.4's **upper** bound, deliberately, because the cookie is
     * not the authority: {@see DocsSession::isLive()} enforces both
     * the idle timeout and the absolute ceiling server-side on every use. A
     * cookie that expired earlier than the row would log a reader out while a
     * revocable session they cannot reach stays live in the inventory, which is
     * the worse of the two inconsistencies.
     */
    public const int SESSION_TTL_MINUTES = 24 * 60;

    /**
     * §12.4's five rows, for the test that asserts the table.
     *
     * @return list<string>
     */
    public static function names(): array
    {
        return [self::DASHBOARD, self::SESSION, self::GRANT, self::CACHE_KEY, self::STATE];
    }

    /**
     * 🛑 The attributes every row of §12.4 carries, as data.
     *
     * @return array{path: string, domain: null, secure: true, httpOnly: true, sameSite: string}
     */
    public static function attributes(): array
    {
        return [
            /* 🛑 `/` and nothing else: `__Host-` requires it. */
            'path' => '/',
            /* 🛑 Null and never a value: `__Host-` forbids a Domain attribute. */
            'domain' => null,
            'secure' => true,
            'httpOnly' => true,
            'sameSite' => Cookie::SAMESITE_LAX,
        ];
    }

    /** The opaque session handle (§12.4, 8–24 h). */
    public static function session(string $handle): Cookie
    {
        return self::make(self::SESSION, $handle, self::SESSION_TTL_MINUTES * 60);
    }

    /**
     * The grant (§12.4, ≤10 m).
     *
     * 🛑 The cookie's own `Max-Age` is the grant's TTL ceiling rather than the
     * individual token's `exp`. The token is the authority on its own
     * expiry — {@see GrantVerifier} checks it with zero
     * leeway — and a cookie that outlived a stale token by a few minutes
     * simply means the next request presents something the verifier refuses,
     * which §8.12.23 then reads as case (a) and challenges. A cookie that
     * expired *early* would instead leave a reader with a live session and no
     * bearer, which is a silent re-handoff on every page.
     */
    public static function grant(string $token): Cookie
    {
        return self::make(self::GRANT, $token, GrantMinter::MAX_TTL_SECONDS);
    }

    /**
     * Tier B's opaque cache key (§8.12.13).
     *
     * 🛑 "carries no session material" is literal: the value is a second,
     * independent CSPRNG secret stored beside the session, never the handle and
     * never derived from it. Its value lands in an nginx cache key on disk.
     */
    public static function cacheKey(string $value): Cookie
    {
        return self::make(self::CACHE_KEY, $value, GrantMinter::MAX_TTL_SECONDS);
    }

    /** The PKCE verifier and return path, for the 5 minutes of a handoff. */
    public static function state(string $value): Cookie
    {
        return self::make(self::STATE, $value, self::STATE_TTL_SECONDS);
    }

    /**
     * An expiry for one of the four, for a logout or a failed handoff.
     *
     * 🛑 Carries the **same** attributes as the cookie it clears. A clearing
     * cookie whose path or domain differs is a new cookie the browser stores
     * beside the old one, and the old one keeps being sent.
     */
    public static function forget(string $name): Cookie
    {
        return self::make($name, '', -3600);
    }

    private static function make(string $name, string $value, int $ttlSeconds): Cookie
    {
        /*
         * 🛑 The four attributes are **literals here**, not read back out of
         * {@see self::attributes()}, and that is not duplication for its own
         * sake: Symfony types `$sameSite` as `''|'lax'|'none'|'strict'|null`, so
         * passing it through an array loses the literal type and Larastan
         * refuses the call at level 8. `attributes()` exists for the test that
         * asserts §12.4's table as data; this is the one construction site, and
         * the test is what keeps the two in step.
         */
        return new Cookie(
            name: $name,
            value: $value,
            expire: $ttlSeconds === 0 ? 0 : time() + $ttlSeconds,
            /* 🛑 `/` and nothing else: `__Host-` requires it. */
            path: '/',
            /* 🛑 Null and never a value: `__Host-` forbids a Domain attribute. */
            domain: null,
            secure: true,
            httpOnly: true,
            raw: false,
            sameSite: Cookie::SAMESITE_LAX,
        );
    }
}
