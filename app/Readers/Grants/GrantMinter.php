<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers\Grants;

use App\Access\AccessDecision;
use App\Access\AccessSurface;
use App\Readers\SessionRecord;
use App\Support\Uuid;
use Firebase\JWT\JWT;

/**
 * §8.12.11's minting half: one {@see AccessDecision} becomes one signed grant.
 *
 * > "Public-key verification lets the edge verify and never mint."
 *
 * 🛑 **Only an allow is mintable.** A denial produces no token at all, rather
 * than a token saying "denied": a grant is a bearer credential, and a bearer
 * credential whose meaning depends on reading a field inside it is one
 * misconfigured verifier away from being a bearer credential that allows. The
 * absence of a grant is unambiguous at every tier.
 *
 * 🛑 **An `EdDSA` JWT, not a bespoke envelope**, and §8.12.12 is the reason:
 *
 * > "no second cryptographic verifier of DocUp's own design MUST be
 * > implemented in an edge scripting language."
 *
 * A standard JWS means Tier C's verifier is an off-the-shelf library in
 * whatever language the edge speaks, and the algorithm is pinned explicitly at
 * both ends — a `Key` carrying its own algorithm on the way in, a literal
 * `EdDSA` on the way out — so the `alg`-confusion class cannot arise from a
 * header the token itself supplies.
 */
final readonly class GrantMinter
{
    /**
     * 🛑 §8.12.11's ceiling: "`exp` ≤ 10 minutes".
     *
     * The ceiling is what bounds Tier C's exposure window (§8.12.15: "the
     * unexpired grant's remaining TTL plus the epoch-feed interval"), so it is
     * a constant here rather than configuration. An operator who could raise it
     * would be raising the one number §4.2's "no sub-second revocation"
     * non-goal is scoped by.
     */
    public const int MAX_TTL_SECONDS = 600;

    /** The default, well inside the ceiling, when no rule narrows it. */
    public const int DEFAULT_TTL_SECONDS = 300;

    public function __construct(private GrantKeys $keys) {}

    /**
     * Mint a grant for an allowed decision.
     *
     * @param  string  $domainId  raw 16 bytes — 🛑 the audience. §17: "a grant
     *                            minted for domain A is refused on domain B".
     * @param  string  $versionId  raw 16 bytes
     * @param  int  $authzEpoch  the project's current `authz_epoch`
     * @param  int  $identityEpoch  the project's current `identity_epoch`
     * @param  int|null  $ttlSeconds  an explicit override; null takes the
     *                                satisfying rule's `grant_ttl_seconds` and
     *                                falls back to the default. Clamped to
     *                                {@see self::MAX_TTL_SECONDS} either way.
     * @param  int|null  $now  unix seconds; null reads the clock
     * @return string the compact JWS
     *
     * @throws \InvalidArgumentException when the decision is not an allow
     */
    public function mint(
        AccessDecision $decision,
        SessionRecord $session,
        string $domainId,
        string $versionId,
        string $versionSlug,
        int $authzEpoch,
        int $identityEpoch,
        AccessSurface $surface = AccessSurface::Proxy,
        ?int $ttlSeconds = null,
        ?int $now = null,
    ): string {
        if (! $decision->allowed) {
            /*
             * 🛑 Not a soft failure. A caller reaching here with a denial has a
             * control-flow bug, and returning null would let it be ignored at
             * a call site whose next line sets a cookie.
             */
            throw new \InvalidArgumentException('a grant may only be minted for an allowed decision');
        }

        $now ??= time();

        /*
         * 🛑 Clamped, not validated. A rule carrying a larger TTL is a row
         * somebody wrote, possibly before this ceiling existed; refusing the
         * request would turn a stale configuration into an outage, while
         * clamping makes the ceiling true regardless of what the row says. The
         * write path refuses the value too — two defences, one of which cannot
         * be bypassed by an older row.
         */
        /*
         * Written as a ternary rather than `?->` on the left of `??`, which
         * Larastan flags as redundant: `$decision->rule` is narrowed non-null
         * inside the branch, so the nullsafe reads as a guard against something
         * that cannot happen — which is exactly the kind of guard that survives
         * into code where it hides a real null.
         */
        $fromRule = $decision->rule === null ? null : $decision->rule->grantTtlSeconds;
        $requested = $ttlSeconds ?? $fromRule ?? self::DEFAULT_TTL_SECONDS;
        $ttl = max(min($requested, self::MAX_TTL_SECONDS), 1);

        $grant = new Grant(
            sessionId: $session->id,
            domainId: $domainId,
            projectId: $session->projectId,
            versionId: $versionId,
            versionSlug: $versionSlug,
            ruleId: $decision->rule?->id,
            combinedEpoch: Grant::combinedEpoch($authzEpoch, $identityEpoch),
            issuedAt: $now,
            expiresAt: $now + $ttl,
            surface: $surface,
            level: $decision->established,
            satisfiedBy: $decision->satisfiedBy,
        );

        $key = $this->keys->signing();
        $secret = $this->keys->secretKey($key);

        $token = JWT::encode(
            self::claims($grant),
            base64_encode($secret),
            'EdDSA',
            $key->kid,
        );

        sodium_memzero($secret);

        return $token;
    }

    /**
     * The claim set, as JSON.
     *
     * 🛑 Short claim names, and that is not golf. The grant rides in a cookie
     * on **every** request to a documentation origin, including every one of
     * the sixty assets §8.12.13's Tier B measurement counts; §9.2's request
     * budget is spent on bytes as much as on time, and a `project_version_id`
     * claim name costs more than the identifier it labels.
     *
     * @return array<string, mixed>
     */
    public static function claims(Grant $grant): array
    {
        $issuer = config('docup.origins.app');

        $claims = [
            'iss' => is_string($issuer) ? $issuer : '',
            /* 🛑 The audience is the DOMAIN. See {@see Grant}. */
            'aud' => Uuid::toText($grant->domainId),
            'sub' => Uuid::toText($grant->sessionId),
            'iat' => $grant->issuedAt,
            'exp' => $grant->expiresAt,
            'pid' => Uuid::toText($grant->projectId),
            'vid' => Uuid::toText($grant->versionId),
            'vsl' => $grant->versionSlug,
            'ep' => $grant->combinedEpoch,
            'sfc' => $grant->surface->value,
            'lvl' => $grant->level->value,
        ];

        if ($grant->satisfiedBy !== null) {
            $claims['lf'] = $grant->satisfiedBy->value;
        }

        if ($grant->ruleId !== null) {
            $claims['rid'] = Uuid::toText($grant->ruleId);
        }

        if ($grant->pathPrefix !== null) {
            $claims['pfx'] = $grant->pathPrefix;
        }

        return $claims;
    }
}
