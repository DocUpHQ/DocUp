<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Oidc;

use App\Egress\EgressRefused;
use App\Egress\HardenedEgressClient;
use Illuminate\Support\Facades\Cache;

/**
 * The provider's discovery document, fetched once and cached.
 *
 * 🛑 **Through `HardenedEgressClient`, and §8.3.9's own architecture test names
 * this exact case**: "a second outbound path … gets written in a hurry, for a
 * webhook or an avatar fetch **or an OIDC discovery document**, by somebody who
 * did not know this class existed — and it is the one the attacker uses,
 * because it is the one with no address policy, no pin and no redirect
 * refusal."
 *
 * That sentence was written four phases before this one, and it is the reason
 * §13.2's `league/oauth2-client` is **not** used here — see the build log's
 * Phase 24 entry for the proposed amendment. An issuer URL is operator-supplied
 * configuration pointing at a host DocUp will send a client secret to, which is
 * precisely the input §8.3.9 exists for: resolve-then-pin, no redirects, a
 * private-address refusal and a byte cap.
 *
 * 🛑 **The URL is built from the issuer, not configured separately.** OpenID
 * Connect Discovery §4 fixes it at `<issuer>/.well-known/openid-configuration`,
 * and letting an operator set it independently would mean the issuer DocUp
 * compares `iss` against and the document DocUp trusts could name different
 * hosts.
 */
final readonly class Discovery
{
    /**
     * 🛑 Long, because a discovery document is near-static and every fetch is
     * an outbound request on a reader's critical path. A provider changing an
     * endpoint does so on a maintenance schedule, not between two logins —
     * and `docup:auth:probe` refreshes on demand for the case where they did.
     */
    public const int CACHE_SECONDS = 3600;

    /** A discovery document larger than this is not one. */
    private const int MAX_BYTES = 64 * 1024;

    public function __construct(private HardenedEgressClient $egress) {}

    /**
     * @param  string  $bindingId  raw 16 bytes; scopes the cache
     * @param  string  $issuer  the binding's configured issuer, with no
     *                          trailing slash
     *
     * @throws OidcRefused
     */
    public function metadataFor(string $bindingId, string $issuer): ProviderMetadata
    {
        $document = Cache::remember(
            'oidc:discovery:'.bin2hex($bindingId),
            self::CACHE_SECONDS,
            fn (): array => $this->fetch($issuer),
        );

        try {
            return ProviderMetadata::fromDocument($document, $issuer);
        } catch (OidcRefused $e) {
            /*
             * 🛑 Forget the cached document on a validation failure, for the
             * reason {@see JwksStore} forgets a broken key set: a provider that
             * served one bad document must not have broken every login for the
             * cache lifetime, and an operator who fixes it should see the fix
             * on the next request rather than in an hour.
             */
            Cache::forget('oidc:discovery:'.bin2hex($bindingId));

            throw $e;
        }
    }

    /** Fetch now, bypassing the cache, for a probe. */
    public function refresh(string $bindingId, string $issuer): ProviderMetadata
    {
        Cache::forget('oidc:discovery:'.bin2hex($bindingId));

        return $this->metadataFor($bindingId, $issuer);
    }

    /**
     * @return array<string, mixed>
     *
     * @throws OidcRefused
     */
    private function fetch(string $issuer): array
    {
        $url = rtrim($issuer, '/').'/.well-known/openid-configuration';

        try {
            $response = $this->egress->get($url, ['Accept' => 'application/json']);
        } catch (EgressRefused $e) {
            throw OidcRefused::of(
                OidcRejection::DiscoveryFailed,
                'discovery could not be fetched: '.$e->rejection->value,
            );
        }

        if (! $response->successful()) {
            throw OidcRefused::of(
                OidcRejection::DiscoveryFailed,
                'the discovery endpoint answered '.$response->status,
            );
        }

        if (strlen($response->body) > self::MAX_BYTES) {
            throw OidcRefused::of(
                OidcRejection::DiscoveryFailed,
                'the discovery document exceeds '.self::MAX_BYTES.' bytes',
            );
        }

        $decoded = $response->json();

        if ($decoded === null) {
            throw OidcRefused::of(OidcRejection::DiscoveryFailed, 'the discovery document is not JSON');
        }

        return $decoded;
    }
}
