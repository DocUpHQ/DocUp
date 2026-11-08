<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Drivers;

use App\Access\AccessLeaf;
use App\Auth\Providers\AttemptResult;
use App\Auth\Providers\AuthComponent;
use App\Auth\Providers\BindingContext;
use App\Auth\Providers\BindingRefused;
use App\Auth\Providers\BindingRejection;
use App\Auth\Providers\Federation\ProvisioningMode;
use App\Auth\Providers\ProbeResult;
use App\Auth\Providers\ReaderPresentation;
use App\Auth\Providers\Saml\AuthnRequest;

/**
 * §8.12.17's `saml`: a reader a SAML identity provider vouched for.
 *
 * 🛑 **This driver conducts no protocol**, exactly as `OidcDriver` does not —
 * §8.12.18's "protocol validation MUST be framework-enforced, not
 * driver-optional". The SAML case is the one where that rule earns its keep:
 * every notorious SAML vulnerability of the last decade was a *service
 * provider* validating its own XML, and most were reachable by configuration.
 * So the boundary (`SafeXml`), the signature gate (`SignatureVerifier`), the
 * response rules (`ResponseValidator`) and the replay cache
 * (`AssertionReplayCache`) are `final` classes taking facts rather than
 * options, the controllers drive them, and by the time this driver is consulted
 * the reader already holds a session.
 *
 * ## 🛑 Why `attempt()` reads a session rather than an assertion
 *
 * A SAML reader presents nothing on a documentation request. The assertion was
 * POSTed to the ACS on the dashboard origin, minutes ago; §8.12.10's handoff
 * turned it into a per-origin session and §8.12.11's grant carries the
 * decision. So this driver is `OidcDriver`'s twin: satisfied only when the
 * session's reader identity belongs to **this** binding, so a reader vouched
 * for by provider A does not satisfy a rule naming provider B, and a dashboard
 * member satisfies neither.
 *
 * ## 🛑 What a SAML binding cannot do, and why the config is so small
 *
 * - **No signed `<AuthnRequest>`.** DocUp does not hold a signing key for SAML,
 *   so a provider that *mandates* signed requests cannot be used. ADR 0013
 *   records this as a capability gap rather than a wrong answer.
 * - **No encrypted assertions.** §8.12.18 refuses "encrypted-assertion-without
 *   -signature", and DocUp implements no decryption at all — so an operator
 *   whose provider insists on encryption cannot use this driver. Stated, not
 *   silently broken: {@see self::probe()} says so.
 * - **No metadata fetch.** The certificate is configured, not discovered. OIDC
 *   has `HardenedEgressClient` for its discovery document because OIDC's keys
 *   rotate behind a URL; a SAML signing certificate is a long-lived value an
 *   operator pastes, and fetching metadata would be a second outbound path
 *   §8.3.9 has opinions about for no benefit.
 */
final class SamlDriver implements AuthComponent
{
    public static function type(): string
    {
        return 'saml';
    }

    public static function leaf(): AccessLeaf
    {
        return AccessLeaf::Binding;
    }

    public static function allowsProjectScope(): bool
    {
        /*
         * §8.12.17's table: `saml` is `any` scope, like `oidc`. One
         * installation binding may serve every project while a single project
         * brings its own identity provider — which §8.12.3's most-specific
         * -of-type resolution is what makes workable.
         */
        return true;
    }

    public static function mayMapDashboardRoles(): bool
    {
        /*
         * 🛑 True **as a driver capability** only, and §8.12.5's wording is the
         * reason the distinction matters:
         *
         * > "Dashboard single sign-on is in scope at **installation and
         * > organisation scope only** … Project-scoped bindings MUST NOT
         * > produce any dashboard role, enforced both as a driver capability
         * > flag and as a validation invariant on group mappings."
         *
         * So this flag says "this driver *can* map roles"; the **scope** check
         * says whether this binding may. Both are needed and they answer
         * different questions — `GroupMappings::add()` refuses the project
         * case, a database CHECK refuses it again, and the shared
         * `ReaderProvisioning` refuses it a fourth time at login for rows that
         * predate the others.
         */
        return true;
    }

    /**
     * 🛑 Validate and **normalise**, refusing rather than correcting.
     *
     * @param  array<string, mixed>  $config
     * @return array<string, mixed> the normalised config to store
     *
     * @throws BindingRefused
     */
    public function validate(array $config): array
    {
        $entityId = $config['idp_entity_id'] ?? null;

        if (! is_string($entityId) || $entityId === '') {
            throw BindingRefused::of(BindingRejection::ConfigInvalid, 'saml needs an `idp_entity_id`');
        }

        /*
         * 🛑 A URI, not necessarily a URL, and **not** fetched. SAML Core
         * §8.3.6 makes an entity id any absolute URI up to 1024 characters, and
         * providers do use `urn:` forms. What matters is that it is compared
         * byte-for-byte against the response's `<Issuer>`, so the only
         * normalisation permitted is none.
         */
        if (mb_strlen($entityId) > 1024) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '`idp_entity_id` must be at most 1024 characters (SAML Core §8.3.6)',
            );
        }

        $sso = $config['sso_url'] ?? null;

        if (! is_string($sso) || $sso === '') {
            throw BindingRefused::of(BindingRejection::ConfigInvalid, 'saml needs an `sso_url`');
        }

        $parts = parse_url($sso);

        /*
         * 🛑 Absolute HTTPS, no fragment. The reader is redirected here with a
         * `SAMLRequest` in the query, so a scheme-relative or `http` endpoint
         * would put an authentication request on the wire in clear — and a
         * fragment would be dropped by the browser along with DocUp's
         * parameters.
         *
         * A query string **is** allowed: several providers publish an SSO
         * endpoint carrying one, and `AuthnRequest::redirectUrl()` merges
         * DocUp's parameters over it rather than replacing it.
         */
        if ($parts === false || ($parts['scheme'] ?? '') !== 'https' || ($parts['host'] ?? '') === '') {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '`sso_url` must be an absolute https URL',
            );
        }

        if (isset($parts['fragment'])) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '`sso_url` must carry no fragment; a browser would drop it',
            );
        }

        $certificate = $config['certificate'] ?? null;

        if (! is_string($certificate) || $certificate === '') {
            throw BindingRefused::of(BindingRejection::ConfigInvalid, 'saml needs a `certificate`');
        }

        $normalised = [
            'idp_entity_id' => $entityId,
            'sso_url' => $sso,
            'certificate' => $this->normalisedCertificate($certificate),
        ];

        $mode = $config['provisioning'] ?? null;

        if ($mode !== null) {
            if (! is_string($mode) || ProvisioningMode::tryFrom($mode) === null) {
                throw BindingRefused::of(
                    BindingRejection::ConfigInvalid,
                    '`provisioning` must be disabled, create_reader or create_reader_and_map_groups',
                );
            }

            $normalised['provisioning'] = $mode;
        }

        $groupsAttribute = $config['groups_attribute'] ?? null;

        if ($groupsAttribute !== null) {
            /*
             * The attribute's **Name**, which is a provider decision: Keycloak
             * sends `groups`, ADFS sends a claim URI like
             * `http://schemas.xmlsoap.org/claims/Group`. So the grammar has to
             * admit a URI, which is why it is wider than OIDC's claim-name
             * pattern — but still a single token with no whitespace, because a
             * value that may contain a space is a value that may contain
             * anything.
             */
            if (! is_string($groupsAttribute)
                || preg_match('/^[A-Za-z0-9_.:\/#?=&%+-]{1,255}$/', $groupsAttribute) !== 1) {
                throw BindingRefused::of(
                    BindingRejection::ConfigInvalid,
                    '`groups_attribute` must be 1-255 characters of an attribute name or claim URI',
                );
            }

            $normalised['groups_attribute'] = $groupsAttribute;
        }

        /*
         * 🛑 Only the known keys are returned, so an unknown one is dropped
         * rather than stored — the choice `OidcDriver::validate()` makes and
         * §8.14.1 makes for theme tokens. A config key nothing reads is a key
         * an operator believes is doing something, and here that belief would
         * be about a security control.
         */
        return $normalised;
    }

    public function probe(BindingContext $binding): ProbeResult
    {
        $entityId = $binding->string('idp_entity_id');
        $sso = $binding->string('sso_url');
        $certificate = $binding->string('certificate');

        if ($entityId === null || $sso === null || $certificate === null) {
            return ProbeResult::fail('the binding is missing an entity id, SSO URL or certificate');
        }

        /*
         * 🛑 The probe does **not** fetch, and that is the difference from
         * `OidcDriver::probe()`. There is nothing to fetch: SAML's trust anchor
         * is the configured certificate, not a discovery document. So what is
         * checked is what can be: that the certificate parses, that it is a key
         * type `SignatureVerifier` will accept, and that it has not expired.
         *
         * A certificate that expires next week is the single most common way a
         * working SAML integration stops working, and §8.12.19's automated
         * probe is the only thing positioned to notice before a reader does.
         */
        $parsed = openssl_x509_parse($certificate);

        if ($parsed === false) {
            return ProbeResult::fail('the configured certificate is not a parsable X.509 certificate');
        }

        $notAfter = $parsed['validTo_time_t'] ?? null;

        if (! is_int($notAfter)) {
            return ProbeResult::fail('the certificate carries no usable expiry');
        }

        if ($notAfter <= time()) {
            return ProbeResult::fail(
                'the signing certificate expired on '.gmdate('Y-m-d', $notAfter),
                ['expired_at' => gmdate('c', $notAfter)],
            );
        }

        $public = openssl_pkey_get_public($certificate);

        if ($public === false) {
            return ProbeResult::fail('the certificate carries no public key DocUp can verify with');
        }

        $details = openssl_pkey_get_details($public);

        if ($details === false
            || ! in_array($details['type'] ?? null, [OPENSSL_KEYTYPE_RSA, OPENSSL_KEYTYPE_EC], true)) {
            /*
             * 🛑 RSA or EC only, matching `SignatureVerifier`'s allowlist. A
             * DSA certificate would configure cleanly and then fail every
             * login, because `SIGNATURE_ALGORITHMS` names no `dsa-*` method —
             * so refusing it here turns a mystery into a probe failure.
             */
            return ProbeResult::fail('the certificate key type is neither RSA nor EC');
        }

        $days = (int) floor(($notAfter - time()) / 86400);

        return ProbeResult::pass(
            'certificate valid for '.$days.' more day(s); unsigned requests, unencrypted assertions',
            [
                'idp_entity_id' => $entityId,
                'sso_url' => $sso,
                'acs_url' => AuthnRequest::acsUrl(),
                'sp_entity_id' => AuthnRequest::entityId(),
                'certificate_expires' => gmdate('c', $notAfter),
            ],
        );
    }

    public function attempt(BindingContext $binding, ReaderPresentation $presented): AttemptResult
    {
        $subject = $presented->sessionSubject;

        /*
         * 🛑 Satisfied only when the session was established through **this**
         * binding — `OidcDriver::attempt()`'s rule, for the same reason.
         * `sessionBinding` is the binding that vouched for the session's reader
         * identity, or null for a dashboard member's session.
         *
         * `hash_equals` because both sides are raw 16 bytes and the comparison
         * decides access.
         */
        if ($subject === null || $presented->sessionBinding === null) {
            return AttemptResult::unsatisfied();
        }

        if (! hash_equals($binding->id, $presented->sessionBinding)) {
            return AttemptResult::unsatisfied();
        }

        /*
         * 🛑 No scope. §12.3's last conjunct narrows for `{share}` and
         * `{bearer}`, which are credentials with a stated reach. An
         * IdP-authenticated reader is admitted by whatever the rule says —
         * their groups shape *which* rules match, not how far one reaches.
         */
        return AttemptResult::satisfiedBy(AccessLeaf::Binding, subject: $subject);
    }

    /**
     * 🛑 A bare base64 body wrapped back into PEM, and nothing else changed.
     *
     * Every identity provider's administration UI hands the certificate over
     * differently: Keycloak shows a bare base64 blob, Okta offers a `.pem`
     * download, ADFS gives DER. The first two differ only in the armour, and an
     * operator who pastes the bare form into a field that demands PEM gets a
     * `ConfigInvalid` naming a format they have never heard of.
     *
     * So the armour is added when it is missing — which is **not** "correcting"
     * in the sense `validate()` refuses to do, because the certificate's own
     * bytes are untouched: a blob that is not a certificate still fails below.
     * Whitespace inside the body is stripped for the same reason, since a
     * copy-paste from a web page carries the UI's line wrapping.
     *
     * @throws BindingRefused
     */
    private function normalisedCertificate(string $certificate): string
    {
        $trimmed = trim($certificate);

        if (! str_contains($trimmed, '-----BEGIN')) {
            $body = preg_replace('/\s+/', '', $trimmed) ?? '';

            if (preg_match('/^[A-Za-z0-9+\/=]+$/', $body) !== 1) {
                throw BindingRefused::of(
                    BindingRejection::ConfigInvalid,
                    '`certificate` is neither PEM nor a base64 certificate body',
                );
            }

            $trimmed = "-----BEGIN CERTIFICATE-----\n"
                .chunk_split($body, 64, "\n")
                ."-----END CERTIFICATE-----\n";
        }

        /*
         * 🛑 Parsed before it is stored. §8.12.19's probe would catch an
         * unusable certificate eventually, but a binding that cannot possibly
         * work should not be storable — the operator is *here*, with the
         * provider's UI open in the next tab, and this is the only moment the
         * error costs them nothing.
         */
        if (openssl_x509_parse($trimmed) === false) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '`certificate` is not a parsable X.509 certificate',
            );
        }

        return $trimmed;
    }
}
