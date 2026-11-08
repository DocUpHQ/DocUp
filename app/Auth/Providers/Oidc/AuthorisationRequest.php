<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Oidc;

/**
 * 🛑 The authorisation URL, built so that §8.12.18's mandatory parts cannot be
 * omitted.
 *
 * > "PKCE S256 mandatory … no implicit flow."
 *
 * **Mandatory** is implemented as *absent from the signature*. There is no
 * `$usePkce`, no `$responseType` and no `$codeChallengeMethod` parameter:
 * `response_type` is the literal `code`, `code_challenge_method` is the literal
 * `S256`, and the challenge is derived from a verifier the caller must supply.
 * A driver cannot build a request without PKCE because this class cannot build
 * one, and this class is the only thing that builds one.
 *
 * That is the difference between a validated option and a structural
 * guarantee, and §8.12.18's "not driver-optional" is asking for the second.
 *
 * 🛑 **`redirect_uri` is one fixed URL on the dashboard origin**, not the
 * reader's documentation host. ADR 0008 measured exactly this on Keycloak
 * 26.0.8: one registered callback served readers arriving from two different
 * custom domains, and an *unregistered* per-domain URI was correctly refused —
 * so a per-domain design would need every custom domain registered with every
 * provider. The originating domain travels in `state` instead, where
 * {@see OidcExchange} treats it as an index into a stored row rather than as a
 * URL.
 */
final readonly class AuthorisationRequest
{
    /**
     * 🛑 The scopes DocUp asks for, and nothing more.
     *
     * `openid` because it is what makes this OIDC rather than OAuth. `profile`
     * for the display label an operator sees in a session inventory — and
     * **not** `email`: §8.12.1 says "email MUST NEVER be used for linking or
     * lookup", and a scope DocUp does not need is personal data DocUp should
     * not be holding (§8.22's minimisation, and a third-country transfer
     * question it need not answer).
     *
     * Groups are requested per binding, because the claim's name is a provider
     * decision — Keycloak says `groups`, Entra says `roles` — so the scope that
     * carries it is configuration rather than a constant.
     *
     * @var list<string>
     */
    public const array BASE_SCOPES = ['openid', 'profile'];

    /**
     * Build the URL to send the reader to.
     *
     * @param  string  $state  the opaque index into the stored exchange
     * @param  string  $nonce  single-use, checked against the id_token
     * @param  string  $verifier  the PKCE verifier; the challenge is derived
     * @param  list<string>  $extraScopes  the binding's group scope, if any
     *
     * @throws OidcRefused
     */
    public static function url(
        ProviderMetadata $metadata,
        string $clientId,
        string $redirectUri,
        string $state,
        string $nonce,
        string $verifier,
        array $extraScopes = [],
    ): string {
        /*
         * 🛑 RFC 7636 §4.1: 43 to 128 characters from the unreserved set. A
         * short verifier is a weak one, so the floor is checked rather than
         * assumed — {@see OidcExchange::open()} generates 128, and this is what
         * would catch a future caller that generated its own.
         */
        if (strlen($verifier) < 43 || preg_match('/^[A-Za-z0-9._~-]{43,128}$/', $verifier) !== 1) {
            throw OidcRefused::of(
                OidcRejection::PkceMissing,
                'the PKCE verifier is not 43-128 unreserved characters (RFC 7636 §4.1)',
            );
        }

        /*
         * 🛑 S256, computed here. RFC 7636 §4.2: BASE64URL(SHA256(ASCII(
         * verifier))). The `plain` method is not implemented — not disabled, not
         * discouraged: there is no branch that could select it.
         */
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        $scopes = self::BASE_SCOPES;

        foreach ($extraScopes as $scope) {
            if ($scope !== '' && ! in_array($scope, $scopes, true)) {
                $scopes[] = $scope;
            }
        }

        $parameters = [
            /* 🛑 `code`, literally. §8.12.18: "no implicit flow". */
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'scope' => implode(' ', $scopes),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $challenge,
            /* 🛑 `S256`, literally. §8.12.18: "PKCE S256 mandatory". */
            'code_challenge_method' => 'S256',
            /*
             * 🛑 `response_mode=query`, stated rather than defaulted.
             *
             * The code flow's default is already `query`, so this changes
             * nothing today — and that is the point: it closes the door on a
             * provider or a proxy choosing `fragment`, where the code would
             * never reach the server and a reader would see a silent failure.
             * It is also the parameter an attacker would add if they could.
             */
            'response_mode' => 'query',
        ];

        /*
         * 🛑 The endpoint's own query is **merged**, not clobbered.
         *
         * RFC 6749 §3.1 allows an authorization endpoint to carry a query
         * string, and some providers use one. Appending `?` blindly would
         * produce two, and appending `&` blindly breaks an endpoint without
         * one — but the interesting case is the third: a provider's own
         * parameter must not be able to shadow one DocUp sets, so DocUp's are
         * merged *over* theirs.
         */
        $parts = parse_url($metadata->authorizationEndpoint);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            throw OidcRefused::of(
                OidcRejection::DiscoveryFailed,
                'the authorization endpoint is not a usable URL',
            );
        }

        $existing = [];

        if (isset($parts['query'])) {
            parse_str($parts['query'], $existing);
        }

        $query = http_build_query(array_merge($existing, $parameters), '', '&', PHP_QUERY_RFC3986);

        $base = $parts['scheme'].'://'.$parts['host']
            .(isset($parts['port']) ? ':'.$parts['port'] : '')
            .($parts['path'] ?? '');

        return $base.'?'.$query;
    }

    /**
     * The one callback URL, on the dashboard origin.
     *
     * 🛑 Built from `docup.origins.app` rather than from the request, for the
     * reason §8.12.10 gives about return URLs: a `redirect_uri` taken from the
     * request is a `redirect_uri` the reader chooses, and the provider's
     * allowlist is the only thing that would catch it — which is to say, the
     * security of DocUp's callback would depend on somebody else's
     * configuration being right.
     *
     * @throws OidcRefused
     */
    public static function callbackUrl(): string
    {
        $host = config('docup.origins.app');

        if (! is_string($host) || $host === '') {
            throw OidcRefused::of(
                OidcRejection::ConfigInvalid,
                'the dashboard origin is not configured, so there is no callback URL',
            );
        }

        /*
         * `docup.origins.app` is a **host**, not a URL — the trap Phase 22 hit
         * when `startUrl()` built a schemeless `Location` header and browsers
         * read it as a path.
         */
        return 'https://'.$host.'/_/auth/oidc/callback';
    }
}
