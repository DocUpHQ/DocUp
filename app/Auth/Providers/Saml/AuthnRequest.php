<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Saml;

/**
 * 🛑 The `<AuthnRequest>` DocUp sends, built so §8.12.18's rules cannot be
 * omitted.
 *
 * The same shape `App\Auth\Providers\Oidc\AuthorisationRequest` has, and
 * for the same reason: "**mandatory**" is implemented as *absent from the
 * signature*. There is no `$allowIdpInitiated`, no `$forceAuthn` option bag and
 * no way to leave out the `AssertionConsumerServiceURL` — because a driver that
 * could omit any of those is a driver whose validation is optional, which
 * §8.12.18 forbids by name.
 *
 * ## 🛑 What the request is *for*, beyond starting a login
 *
 * Its `ID` is what the response's `InResponseTo` must match. That single fact
 * is how §8.12.18's "IdP-initiated off by default" is enforced — not by a flag,
 * but because a response DocUp did not ask for carries no request id to match.
 * So the request is not ceremony: it is the thing that makes the response
 * bindable to a reader's own session.
 *
 * ## 🛑 `RelayState` is SAML's `state`, and it is an index
 *
 * The originating documentation domain travels in `RelayState`, which the SAML
 * Web Browser SSO Profile requires the identity provider to "return unmodified"
 * — so it round-trips like OIDC's `state`. ADR 0008's warning applies
 * identically: it is reader-supplied on the way back and must be treated as an
 * **index into verified state, never as a URL**. {@see SamlExchange} is that
 * index.
 *
 * ## One ACS URL, on the dashboard origin
 *
 * §18.9's unmeasured half. ADR 0008 measured it for OIDC and recorded that SAML
 * "validates differently — `AssertionConsumerServiceURL` on the request and
 * `Destination` on the response, against the registered ACS", so the same
 * question needs asking again. Built for one fixed URL because that is the
 * shape §8.12.10 wants and the schema already assumes; the build log records
 * the measurement.
 */
final readonly class AuthnRequest
{
    /**
     * 🛑 The only binding DocUp sends a request over: HTTP-Redirect.
     *
     * HTTP-POST for the *response* (which is what the ACS receives) and
     * HTTP-Redirect for the *request*, which is the ordinary Web Browser SSO
     * pairing. HTTP-Artifact is deliberately absent: it requires a back-channel
     * SOAP resolver, which would be a second outbound path §8.3.9 has
     * opinions about, for no benefit DocUp needs.
     */
    public const string BINDING_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

    /** What the identity provider must POST the response back over. */
    public const string BINDING_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

    /**
     * 🛑 `persistent`, not `transient` and not `emailAddress`.
     *
     * §8.12.1: "Reader identities MUST be keyed `(binding_id, subject_hash)`,
     * **email MUST NEVER be used for linking or lookup**." A `transient`
     * NameID is a different value on every login, so a reader would be a new
     * identity each time and their group mappings would never accumulate; an
     * `emailAddress` NameID is precisely what §8.12.1 forbids.
     *
     * `persistent` is the one format that gives a stable, opaque, per-SP
     * identifier — which is exactly what a `subject_hash` wants.
     */
    public const string NAMEID_PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

    /**
     * Build the request XML and the id the response must answer.
     *
     * @param  string  $destination  the identity provider's SSO endpoint
     * @param  string  $issuer  DocUp's own entity id
     * @param  string  $acs  the one assertion consumer service URL
     * @return array{id: string, xml: string}
     */
    public static function build(
        string $destination,
        string $issuer,
        string $acs,
        ?int $now = null,
    ): array {
        $now ??= time();

        /*
         * 🛑 The request id is CSPRNG, and prefixed with a letter because
         * xsd:ID must not begin with a digit — a numeric id makes a
         * schema-validating identity provider refuse the request with an error
         * that mentions neither.
         */
        $id = '_'.bin2hex(random_bytes(16));

        $document = new \DOMDocument('1.0', 'UTF-8');

        $request = $document->createElementNS(SamlNamespaces::PROTOCOL, 'samlp:AuthnRequest');
        $document->appendChild($request);

        $request->setAttribute('ID', $id);
        $request->setAttribute('Version', '2.0');
        $request->setAttribute('IssueInstant', gmdate('Y-m-d\TH:i:s\Z', $now));
        $request->setAttribute('Destination', $destination);

        /*
         * 🛑 Both, always. The URL is what the identity provider validates
         * against its registered list — ADR 0008's control for OIDC, and the
         * thing §18.9 needs measuring for SAML — and the binding tells it to
         * POST rather than redirect, which is what the ACS route accepts.
         */
        $request->setAttribute('AssertionConsumerServiceURL', $acs);
        $request->setAttribute('ProtocolBinding', self::BINDING_POST);

        $issuerElement = $document->createElementNS(SamlNamespaces::ASSERTION, 'saml:Issuer');
        $issuerElement->appendChild($document->createTextNode($issuer));
        $request->appendChild($issuerElement);

        $policy = $document->createElementNS(SamlNamespaces::PROTOCOL, 'samlp:NameIDPolicy');
        $policy->setAttribute('Format', self::NAMEID_PERSISTENT);

        /*
         * 🛑 `AllowCreate` so a reader who has never signed in to DocUp gets a
         * persistent identifier minted for them. Without it, a provider may
         * refuse the first login of every reader — which presents as "SAML does
         * not work" rather than as a policy decision.
         */
        $policy->setAttribute('AllowCreate', 'true');
        $request->appendChild($policy);

        return ['id' => $id, 'xml' => (string) $document->saveXML()];
    }

    /**
     * The redirect URL for the HTTP-Redirect binding.
     *
     * 🛑 Deflated, base64'd and url-encoded, in that order, which the binding
     * specifies (SAML Bindings §3.4.4.1) — and `gzdeflate` rather than
     * `gzcompress`, because the binding wants a **raw** DEFLATE stream with no
     * zlib header. Using the wrong one produces a request every identity
     * provider refuses with a decode error, which is a long afternoon.
     *
     * @param  string  $relayState  the opaque index into DocUp's stored exchange
     */
    public static function redirectUrl(string $ssoUrl, string $xml, string $relayState): string
    {
        $deflated = gzdeflate($xml, 9);

        if ($deflated === false) {
            throw SamlRefused::of(SamlRejection::ConfigInvalid, 'the authentication request could not be deflated');
        }

        $parts = parse_url($ssoUrl);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            throw SamlRefused::of(SamlRejection::ConfigInvalid, 'the provider SSO URL is not usable');
        }

        $existing = [];

        if (isset($parts['query'])) {
            parse_str($parts['query'], $existing);
        }

        /*
         * 🛑 DocUp's parameters merged **over** the endpoint's own, for the
         * reason Phase 24 gives at the same place: a provider's own query
         * parameter must not be able to shadow one DocUp sets.
         */
        $query = http_build_query(
            array_merge($existing, [
                'SAMLRequest' => base64_encode($deflated),
                'RelayState' => $relayState,
            ]),
            '',
            '&',
            PHP_QUERY_RFC3986,
        );

        return $parts['scheme'].'://'.$parts['host']
            .(isset($parts['port']) ? ':'.$parts['port'] : '')
            .($parts['path'] ?? '')
            .'?'.$query;
    }

    /**
     * DocUp's one assertion consumer service URL.
     *
     * 🛑 Built from `docup.origins.app`, never from the request — the rule
     * §8.12.10 states for return URLs and §8.12.18 relies on for `Destination`.
     * An ACS taken from the request is an ACS the reader chooses, and the
     * provider's registered list would be the only thing catching it.
     *
     * @throws SamlRefused
     */
    public static function acsUrl(): string
    {
        $host = config('docup.origins.app');

        if (! is_string($host) || $host === '') {
            throw SamlRefused::of(
                SamlRejection::ConfigInvalid,
                'the dashboard origin is not configured, so there is no ACS URL',
            );
        }

        /*
         * A **host**, not a URL — the trap Phase 22 hit when `startUrl()` built
         * a schemeless `Location` that browsers read as a path.
         */
        return 'https://'.$host.'/_/auth/saml/acs';
    }

    /**
     * DocUp's SAML entity id, which is what an assertion's `Audience` must name.
     *
     * 🛑 A URL that resolves to DocUp's metadata rather than an opaque string.
     * SAML permits any URI, but every identity provider's administration UI
     * expects to fetch metadata from it, and an entity id nobody can fetch is
     * an entity id an operator will mistype.
     *
     * @throws SamlRefused
     */
    public static function entityId(): string
    {
        $host = config('docup.origins.app');

        if (! is_string($host) || $host === '') {
            throw SamlRefused::of(
                SamlRejection::ConfigInvalid,
                'the dashboard origin is not configured, so there is no entity id',
            );
        }

        return 'https://'.$host.'/saml/metadata';
    }
}
