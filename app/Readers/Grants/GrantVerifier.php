<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers\Grants;

use App\Access\AccessLeaf;
use App\Access\AccessSurface;
use App\Access\EffectiveAccess;
use App\Auth\AccessLevel;
use App\Support\Uuid;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * §8.12.11's verifying half, and the one place the grant's claims become
 * trusted.
 *
 * 🛑 **Every refusal below is a disclosure prevented, and the order matters
 * only in that none may be skipped.** A verifier that checks the signature and
 * reads the claims is the common shape and it is wrong here: the signature
 * proves this installation minted the token, not that the token is for *this*
 * request. The three checks that make it so are the audience, the epoch and
 * the surface.
 *
 * ## 🛑 Why a failed verification is not a denial
 *
 * This class returns `null` for "no usable grant", never a verdict.
 * {@see EffectiveAccess} decides; a missing or stale grant simply
 * means the request arrives with less established context, and the decision
 * function applies §12.3 to what is left. §8.12.14's "no public fast path"
 * has a mirror image: there is no *private* fast path either, and a grant is
 * an optimisation over re-reading the session, not an authority of its own.
 *
 * 🛑 `credentialRejected` is the one thing a failure does establish, because
 * §8.12.23's case (a) — "a credential was presented and rejected" — is what
 * permits a 401. The caller gets that as a separate boolean rather than
 * inferring it from a null.
 */
final readonly class GrantVerifier
{
    /**
     * 🛑 The only algorithm. Pinned as a literal at both ends: a `Key` carries
     * it on the way in and {@see GrantMinter} passes it on the way out, so the
     * token's own `alg` header is never consulted to choose a verifier. This is
     * the `alg`-confusion class closed structurally rather than by a check.
     *
     * §8.12.18 requires "a signing-algorithm allowlist excluding `none`" for
     * OIDC; an allowlist of one is the strongest form of that, and DocUp's own
     * grant is the one token where it can be a singleton.
     */
    private const string ALGORITHM = 'EdDSA';

    /**
     * Leeway, in seconds, for `exp` and `iat`.
     *
     * 🛑 **Zero**, and that is a decision rather than an omission. Minter and
     * verifier are the same installation reading the same clock, so there is no
     * skew to absorb — and §8.12.15 bounds Tier C's exposure by "the unexpired
     * grant's remaining TTL", a number that leeway would quietly extend.
     */
    private const int LEEWAY = 0;

    public function __construct(private GrantKeys $keys) {}

    /**
     * Verify a presented grant against this request.
     *
     * 🛑 Named `grantFor` rather than `verify`, and the rename is not taste.
     * §8.19.3's architecture test asserts one call site for webhook signature
     * verification by grepping `app/` for `->verify(`, so a method of that name
     * anywhere in the application collides with a gate about something else
     * entirely. Phase 21 hit the same shape with the identifier
     * `publiclyCacheable` and resolved it the same way: rename, never weaken
     * the gate. The name is also more honest — this returns the grant usable
     * for *this* request, which is strictly more than a signature check.
     *
     * @param  string  $token  the compact JWS from §12.4's `__Host-docup_grant`
     * @param  string  $domainId  raw 16 bytes — the domain this request arrived
     *                            on, read from the resolved routing snapshot
     *                            and never from a header
     * @param  int  $currentEpoch  {@see Grant::combinedEpoch()} for the
     *                             project's epochs as they are **now**
     * @param  int|null  $now  unix seconds; null reads the clock
     * @return Grant|null the grant, or null when it cannot be used for this
     *                    request for any reason
     */
    public function grantFor(
        string $token,
        string $domainId,
        int $currentEpoch,
        AccessSurface $surface = AccessSurface::Proxy,
        ?int $now = null,
    ): ?Grant {
        $now ??= time();

        $claims = $this->decode($token);

        if ($claims === null) {
            return null;
        }

        $grant = self::fromClaims($claims);

        if ($grant === null) {
            return null;
        }

        /*
         * 🛑 §17's exit criterion, as one comparison: "A grant minted for
         * domain A is refused on domain B."
         *
         * `firebase/php-jwt` validates `aud` only if asked, and asking it means
         * passing the expected value — so this is here rather than in the
         * decode, where a future refactor could drop the argument and leave the
         * signature check looking like the whole verification.
         */
        if (! hash_equals($grant->domainId, $domainId)) {
            return null;
        }

        /*
         * 🛑 §8.12.13's Tier C condition, applied at Tier A as well: "refuse
         * any grant below the current epoch".
         *
         * At Tiers A and B this is what gives §8.12.15 its one-request bound.
         * The epoch is read from the project row on this request, so a policy
         * edit, a visibility flip or a session revoke invalidates every
         * outstanding grant at the next request — with no purge, exactly as
         * §10.8 requires.
         */
        if ($grant->combinedEpoch < $currentEpoch) {
            return null;
        }

        /*
         * 🛑 A grant for one surface is not a grant for another. §8.12.21 makes
         * search a separately gated surface, and a grant minted while reading a
         * page would otherwise be a search credential — which matters because
         * §8.12.21 disables search entirely while its generation lags, and a
         * proxy grant must not route around that.
         */
        if ($grant->surface !== $surface) {
            return null;
        }

        if (! $grant->isUnexpired($now)) {
            return null;
        }

        return $grant;
    }

    /**
     * Whether a presented token is structurally a grant this installation
     * minted — the input to §8.12.23's case (a).
     *
     * 🛑 Deliberately **weaker** than {@see self::grantFor()}: it answers "was a
     * credential presented", not "is it good". A reader whose grant expired
     * sixty seconds ago presented a credential and should be challenged rather
     * than told the resource does not exist; a reader sending nineteen bytes of
     * noise presented nothing a challenge would help with.
     */
    public function looksLikeGrant(string $token): bool
    {
        return $this->decode($token) !== null;
    }

    /**
     * Signature and structure only.
     *
     * @return array<string, mixed>|null
     */
    private function decode(string $token): ?array
    {
        /*
         * 🛑 The `kid` is read from the header to *select* a key, which is the
         * one legitimate use of an unverified header field — and it can only
         * select among keys this installation published. An unknown or retired
         * `kid` finds nothing and the token is refused; it cannot cause a
         * different algorithm, a different key source or a network fetch.
         */
        $kid = self::headerKid($token);

        if ($kid === null) {
            return null;
        }

        $public = $this->keys->publicKey($kid);

        if ($public === null) {
            return null;
        }

        JWT::$leeway = self::LEEWAY;

        try {
            $decoded = JWT::decode($token, new Key(base64_encode($public), self::ALGORITHM));
        } catch (\Throwable) {
            /*
             * 🛑 Every failure is one outcome: the token is unusable. The
             * library distinguishes an expired token from a bad signature from
             * malformed JSON, and acting on that distinction here would make
             * the response vary with what an attacker sent — which §8.12.23
             * forbids in as many words. {@see self::looksLikeGrant()} is the
             * one place a weaker question is asked, and it asks it of the same
             * code.
             */
            return null;
        }

        /** @var array<string, mixed> $claims */
        $claims = (array) $decoded;

        return $claims;
    }

    /**
     * The `kid` from an unverified JWS header.
     *
     * Parsed by hand rather than by the library, because the library has no
     * API for reading a header before verification — and the parse is
     * deliberately paranoid: three segments, a base64url header that decodes,
     * JSON that is an object, and a `kid` that is a short string. Anything else
     * is not a token this installation minted.
     */
    private static function headerKid(string $token): ?string
    {
        $segments = explode('.', $token);

        if (count($segments) !== 3) {
            return null;
        }

        $raw = base64_decode(strtr($segments[0], '-_', '+/'), true);

        if ($raw === false || $raw === '') {
            return null;
        }

        try {
            $header = json_decode($raw, true, 4, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return null;
        }

        if (! is_array($header)) {
            return null;
        }

        $kid = $header['kid'] ?? null;

        return is_string($kid) && $kid !== '' && strlen($kid) <= 64 ? $kid : null;
    }

    /**
     * A {@see Grant} from verified claims, or null when a claim is missing or
     * the wrong shape.
     *
     * 🛑 Fails closed on **every** field. A grant with no `aud` would pass an
     * audience check written as `$claims['aud'] === $expected` only if that
     * comparison were loose, and a grant with no `ep` would compare `null < 5`
     * as true in some PHP versions and false in others. Every claim is
     * required and typed here, so there is no shape for the checks above to be
     * fooled by.
     *
     * @param  array<string, mixed>  $claims
     */
    public static function fromClaims(array $claims): ?Grant
    {
        /*
         * 🛑 A UUID claim as the **raw 16 bytes** every id column holds.
         *
         * Named `$bytes` rather than `$text`, which is what it was called when
         * Phase 24 found the bug below: a closure named for its input while
         * returning the other representation is a closure that gets reused on a
         * claim where the other representation is wrong.
         */
        $bytes = static function (mixed $value): ?string {
            return is_string($value) ? Uuid::tryToBytes($value) : null;
        };

        $sessionId = $bytes($claims['sub'] ?? null);
        $domainId = $bytes($claims['aud'] ?? null);
        $projectId = $bytes($claims['pid'] ?? null);
        $versionId = $bytes($claims['vid'] ?? null);
        $slug = $claims['vsl'] ?? null;
        $epoch = $claims['ep'] ?? null;
        $issued = $claims['iat'] ?? null;
        $expires = $claims['exp'] ?? null;
        $surface = is_string($claims['sfc'] ?? null) ? AccessSurface::tryFrom((string) $claims['sfc']) : null;

        if ($sessionId === null || $domainId === null || $projectId === null || $versionId === null) {
            return null;
        }

        if (! is_string($slug) || $surface === null) {
            return null;
        }

        if (! is_numeric($epoch) || ! is_numeric($issued) || ! is_numeric($expires)) {
            /*
             * 🛑 `is_numeric` then cast, never `is_int`. Phase 20's finding,
             * and it applies with full force to a JSON claim: `json_decode`
             * gives an int here, but a grant that round-tripped through a
             * cache, a queue payload or an edge's own JSON writer can arrive as
             * a float or a numeric string, and `is_int` would refuse a valid
             * grant rather than accept a bad one — a fail-closed bug, which is
             * still a bug.
             */
            return null;
        }

        /*
         * 🛑 The level fails closed to the **strongest** rung, which is the one
         * no reader reaches without a rule naming the resource — the same
         * direction {@see \App\Access\ReaderGate::level()} fails in, and for
         * the same reason. A grant whose `lvl` this code cannot read must not
         * become a `public` reader who then sails past a public mount.
         */
        $level = is_string($claims['lvl'] ?? null)
            ? AccessLevel::tryFrom((string) $claims['lvl'])
            : null;

        if ($level === null) {
            return null;
        }

        $leaf = is_string($claims['lf'] ?? null) ? AccessLeaf::tryFrom((string) $claims['lf']) : null;

        $prefix = $claims['pfx'] ?? null;
        $ruleId = $bytes($claims['rid'] ?? null);

        /*
         * 🛑 Every entry must parse, and one that does not drops the **whole**
         * list rather than part of it. A partially-read binding list is a
         * reader who satisfies some of the bindings they were vouched for,
         * which is a different reader from the one this installation signed —
         * and the difference would be invisible, because the shorter list only
         * ever refuses.
         */
        /*
         * 🛑 **UUID text, not bytes, and Phase 24 found this the hard way.**
         *
         * §8.12.6's requirement leaf is JSON an operator or an API wrote —
         * `{"leaf": "binding", "binding_id": "<uuid>"}` — and
         * {@see \App\Access\ReaderContext::satisfies()} compares it with
         * `in_array(..., true)`. A strict comparison between 16 bytes and 36
         * characters is always false, so parsing these as bytes made **every
         * rule naming a binding unsatisfiable on the grant path** — which is
         * every request after a reader's first, because the first mints the
         * grant and the rest present it.
         *
         * The shape of the bug is Phase 23's, arriving by the other road: that
         * phase found `ProviderOutcome` storing raw bytes against the same
         * text and fixed the session path. This path was written in Phase 22,
         * before any binding existed, so `bnd` was always empty and the
         * mismatch could not show — the docblock on
         * {@see Grant::$satisfiedBindings} says so in as many words ("Empty
         * throughout Phase 22"). A field that is always empty is a field whose
         * type nothing checks.
         *
         * Found by Phase 24's two-realm exit criterion: a reader's **second**
         * read of their own project 404'd with `requirement_unsatisfied` while
         * the first allowed. The two paths disagreeing is the only symptom this
         * class of bug has.
         */
        $bindings = [];

        foreach (is_array($claims['bnd'] ?? null) ? $claims['bnd'] : [] as $value) {
            /*
             * Validated as a UUID and kept as text. `Uuid::toText()` is
             * idempotent, so this both checks the shape and normalises a claim
             * that arrived in either form.
             */
            if (! is_string($value) || Uuid::tryToBytes($value) === null) {
                return null;
            }

            $bindings[] = Uuid::toText($value);
        }

        return new Grant(
            sessionId: $sessionId,
            domainId: $domainId,
            projectId: $projectId,
            versionId: $versionId,
            versionSlug: $slug,
            ruleId: $ruleId,
            combinedEpoch: (int) $epoch,
            issuedAt: (int) $issued,
            expiresAt: (int) $expires,
            surface: $surface,
            level: $level,
            satisfiedBy: $leaf,
            pathPrefix: is_string($prefix) ? $prefix : null,
            satisfiedBindings: $bindings,
        );
    }
}
