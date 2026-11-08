<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Oidc;

use App\Egress\EgressRefused;
use App\Egress\HardenedEgressClient;

/**
 * The back-channel code exchange.
 *
 * 🛑 **Through `HardenedEgressClient`, and this is the call that carries the
 * client secret.** §8.3.9's one outbound path exists for inputs "derived from
 * user-supplied configuration"; a token endpoint URL comes from a discovery
 * document at an operator-configured issuer, and DocUp posts a secret to it.
 * That is the highest-stakes outbound request in the product after ACME's, and
 * it gets the same resolve-then-pin, the same redirect refusal and the same
 * scheme allowlist as every other.
 *
 * 🛑 **No redirects, which the client already refuses.** RFC 6749 gives the
 * token endpoint no reason to redirect, and a 302 from it is either a
 * misconfiguration or an attempt to move a request carrying a client secret to
 * another host. The egress client refuses every redirect, so this needs no code
 * of its own — stated because the absence of code is the thing a reader of this
 * class would otherwise look for.
 */
final readonly class TokenEndpoint
{
    /**
     * 🛑 A token response larger than this is not one.
     *
     * Generous — an id_token with many group claims is a few kilobytes — and
     * still a bound. `HardenedEgressClient` has its own cap; this is the
     * semantic one, so a provider streaming megabytes gets a named refusal
     * rather than an egress error.
     */
    private const int MAX_BYTES = 128 * 1024;

    public function __construct(private HardenedEgressClient $egress) {}

    /**
     * Exchange an authorisation code for tokens.
     *
     * @param  string  $code  from the callback's query, never trusted beyond
     *                        being passed back to the provider that issued it
     * @param  string  $verifier  the PKCE verifier from the stored exchange
     * @return array{id_token: string, access_token: ?string}
     *
     * @throws OidcRefused
     */
    public function exchange(
        ProviderMetadata $metadata,
        string $clientId,
        ?string $clientSecret,
        string $redirectUri,
        string $code,
        string $verifier,
    ): array {
        $parameters = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'client_id' => $clientId,
            /*
             * 🛑 The verifier, which is what makes the code useless to anybody
             * who intercepted it. RFC 7636's whole purpose, and §8.12.18 makes
             * it mandatory rather than conditional on the client being public.
             */
            'code_verifier' => $verifier,
        ];

        $headers = [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Accept' => 'application/json',
        ];

        if ($clientSecret !== null && $clientSecret !== '') {
            /*
             * 🛑 `client_secret_basic`, not `client_secret_post`.
             *
             * Both are legal (RFC 6749 §2.3.1) and the first is what the
             * specification says clients SHOULD use. The practical difference
             * is where the secret ends up when something goes wrong: a POST
             * body is logged by rather more middleboxes than an `Authorization`
             * header, and DocUp's own `RedactSecrets` already knows to strip
             * that header.
             */
            $headers['Authorization'] = 'Basic '.base64_encode(
                rawurlencode($clientId).':'.rawurlencode($clientSecret)
            );
        }

        try {
            $response = $this->egress->post(
                $metadata->tokenEndpoint,
                http_build_query($parameters, '', '&', PHP_QUERY_RFC1738),
                $headers,
            );
        } catch (EgressRefused $e) {
            throw OidcRefused::of(
                OidcRejection::TokenEndpointFailed,
                'the token endpoint could not be reached: '.$e->rejection->value,
            );
        }

        if (strlen($response->body) > self::MAX_BYTES) {
            throw OidcRefused::of(
                OidcRejection::TokenEndpointFailed,
                'the token response exceeds '.self::MAX_BYTES.' bytes',
            );
        }

        if (! $response->successful()) {
            /*
             * 🛑 The provider's `error` code is **not** included.
             *
             * §8.22.5 keeps free text out of the audit chain, and an
             * `error_description` is free text somebody else wrote — it reaches
             * a log that an operator reads, and a provider is not a trusted
             * source of log content. The status is enough to tell a
             * misconfigured client from an outage.
             */
            throw OidcRefused::of(
                OidcRejection::TokenEndpointFailed,
                'the token endpoint answered '.$response->status,
            );
        }

        $decoded = $response->json();

        if ($decoded === null) {
            throw OidcRefused::of(OidcRejection::TokenEndpointFailed, 'the token response is not JSON');
        }

        $idToken = $decoded['id_token'] ?? null;

        if (! is_string($idToken) || $idToken === '') {
            /*
             * 🛑 No id_token means this was an OAuth exchange, not an OIDC one.
             * There is nothing to establish an identity from — and
             * substituting `userinfo` would be accepting an identity DocUp
             * cannot verify the signature of.
             */
            throw OidcRefused::of(
                OidcRejection::TokenEndpointFailed,
                'the token response carries no id_token',
            );
        }

        $accessToken = $decoded['access_token'] ?? null;

        return [
            'id_token' => $idToken,
            'access_token' => is_string($accessToken) && $accessToken !== '' ? $accessToken : null,
        ];
    }
}
