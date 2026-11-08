<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Oidc;

/**
 * A provider's discovery document, after validation.
 *
 * 🛑 **A value object rather than the decoded array, because the array is
 * attacker-adjacent.** The discovery document comes from a host an operator
 * configured — so not from an attacker directly — but it is the input that
 * decides where DocUp sends a reader and where it sends a client secret. Every
 * field used anywhere else in this namespace is read once, here, checked, and
 * then only ever read from a typed property.
 *
 * 🛑 **The issuer is checked against the URL it was fetched from.** OpenID
 * Connect Discovery §4.3 requires it ("the `issuer` value returned MUST be
 * identical to the Issuer URL that was used as the prefix"), and the reason is
 * the mix-up attack: without it, a provider could claim to be a different
 * issuer and DocUp's later exact-`iss` comparison would be comparing against a
 * value the wrong party chose.
 */
final readonly class ProviderMetadata
{
    /**
     * @param  list<string>  $algorithms  `id_token_signing_alg_values_supported`,
     *                                    intersected with DocUp's own allowlist
     * @param  list<string>  $codeChallengeMethods  `code_challenge_methods_supported`
     */
    private function __construct(
        public string $issuer,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $jwksUri,
        public array $algorithms,
        public array $codeChallengeMethods,
        public ?string $endSessionEndpoint,
    ) {}

    /**
     * Validate a decoded discovery document.
     *
     * @param  array<string, mixed>  $document
     * @param  string  $expectedIssuer  the issuer this binding is configured
     *                                  for; the document must agree
     *
     * @throws OidcRefused
     */
    public static function fromDocument(array $document, string $expectedIssuer): self
    {
        $issuer = self::string($document, 'issuer');

        /*
         * 🛑 Discovery §4.3, and `hash_equals` rather than `===` for the same
         * reason every other comparison in this namespace uses it: the values
         * are attacker-influenced and the comparison is cheap either way.
         */
        if (! hash_equals($expectedIssuer, $issuer)) {
            throw OidcRefused::of(
                OidcRejection::DiscoveryFailed,
                'the discovery document declares a different issuer than the binding is configured for',
            );
        }

        $authorization = self::httpsUrl($document, 'authorization_endpoint');
        $token = self::httpsUrl($document, 'token_endpoint');
        $jwks = self::httpsUrl($document, 'jwks_uri');

        /*
         * 🛑 The algorithm allowlist is DocUp's, **intersected** with the
         * provider's — not taken from the provider.
         *
         * §8.12.18 wants "a signing-algorithm allowlist excluding `none`". A
         * document that advertised `none` must not be able to put it in the
         * allowlist, so the intersection is computed against
         * {@see IdTokenVerifier::ALGORITHMS} and an empty result is a refusal
         * rather than a fallback.
         */
        $advertised = self::stringList($document, 'id_token_signing_alg_values_supported');

        $algorithms = $advertised === []
            /*
             * Discovery makes the field REQUIRED, but a provider that omits it
             * is common enough that refusing outright would be unhelpful. The
             * fallback is DocUp's own allowlist, which is the safe direction:
             * the token's own `alg` is still checked against it.
             */
            ? IdTokenVerifier::ALGORITHMS
            : array_values(array_intersect(IdTokenVerifier::ALGORITHMS, $advertised));

        if ($algorithms === []) {
            throw OidcRefused::of(
                OidcRejection::AlgorithmNotAllowed,
                'the provider advertises no signing algorithm DocUp accepts',
            );
        }

        /*
         * 🛑 S256 must be advertised when the field is present. §8.12.18 makes
         * PKCE S256 mandatory, so a provider that declares only `plain` is one
         * DocUp cannot use — and finding that out at configuration time, from
         * the probe, is far better than at a reader's first login.
         */
        $methods = self::stringList($document, 'code_challenge_methods_supported');

        if ($methods !== [] && ! in_array('S256', $methods, true)) {
            throw OidcRefused::of(
                OidcRejection::PkceMissing,
                'the provider does not advertise PKCE S256, which §8.12.18 makes mandatory',
            );
        }

        $endSession = $document['end_session_endpoint'] ?? null;

        return new self(
            issuer: $issuer,
            authorizationEndpoint: $authorization,
            tokenEndpoint: $token,
            jwksUri: $jwks,
            algorithms: $algorithms,
            codeChallengeMethods: $methods === [] ? ['S256'] : $methods,
            endSessionEndpoint: is_string($endSession) && $endSession !== '' ? $endSession : null,
        );
    }

    /**
     * @param  array<string, mixed>  $document
     *
     * @throws OidcRefused
     */
    private static function string(array $document, string $key): string
    {
        $value = $document[$key] ?? null;

        if (! is_string($value) || $value === '') {
            throw OidcRefused::of(
                OidcRejection::DiscoveryFailed,
                'the discovery document has no usable `'.$key.'`',
            );
        }

        return $value;
    }

    /**
     * 🛑 An absolute **HTTPS** URL, with no query and no fragment.
     *
     * The scheme because a token endpoint over `http` would carry the client
     * secret in clear; the query and fragment because DocUp appends its own
     * parameters to the authorization endpoint and a document that pre-loaded
     * one could shadow a parameter DocUp sets — `redirect_uri`, say.
     *
     * `HardenedEgressClient` enforces the scheme again on the wire. Checked
     * here too so a bad document is refused at probe time, with a reason, and
     * not as an egress error at a reader's login.
     *
     * @param  array<string, mixed>  $document
     *
     * @throws OidcRefused
     */
    private static function httpsUrl(array $document, string $key): string
    {
        $value = self::string($document, $key);

        $parts = parse_url($value);

        if ($parts === false
            || ($parts['scheme'] ?? '') !== 'https'
            || ($parts['host'] ?? '') === ''
            || isset($parts['fragment'])) {
            throw OidcRefused::of(
                OidcRejection::DiscoveryFailed,
                '`'.$key.'` is not an absolute https URL without a fragment',
            );
        }

        /*
         * A query on the authorization endpoint is legal per RFC 6749 §3.1, so
         * it is permitted — but only there, and the request builder merges
         * rather than appends because of it. On the token and JWKS endpoints a
         * query buys nothing and is refused.
         */
        if (isset($parts['query']) && $key !== 'authorization_endpoint') {
            throw OidcRefused::of(
                OidcRejection::DiscoveryFailed,
                '`'.$key.'` carries a query string, which DocUp refuses outside the authorization endpoint',
            );
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $document
     * @return list<string>
     */
    private static function stringList(array $document, string $key): array
    {
        $value = $document[$key] ?? null;

        if (! is_array($value)) {
            return [];
        }

        $out = [];

        foreach ($value as $item) {
            if (is_string($item) && $item !== '') {
                $out[] = $item;
            }
        }

        return $out;
    }
}
