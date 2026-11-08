<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Mtls;

use App\Auth\Providers\Drivers\MtlsDriver;
use App\Auth\Providers\EdgeAssertion;
use App\Auth\Providers\Ldap\LdapRejection;

/**
 * Every way a forwarded client certificate can fail, as a closed vocabulary.
 *
 * 🛑 The same split {@see LdapRejection} makes, and
 * for the same reason — operator fault earns §8.12.19's branded 503, reader
 * fault earns §8.12.23's `deny_status` — with one addition that is specific to
 * this driver and is the thing to understand before changing it.
 *
 * ## 🛑 Why a certificate DocUp cannot parse is not a rejected credential
 *
 * §8.12.23 permits a 401 when "a credential was presented and rejected", and a
 * header holding something that is not a certificate looks exactly like that.
 * It is not, and the difference is a disclosure.
 *
 * A terminator forwards the certificate header on **every** request. If the
 * `format` setting is wrong, every value fails to parse — so classifying that
 * as a rejected credential would turn every private 404 on the installation
 * into a 401, which is an existence oracle for every private project, created
 * by one typo in one environment variable. {@see MtlsDriver} therefore treats
 * {@see self::Unparseable} as an unsatisfied leaf and leaves the diagnosis to
 * the probe, where it costs nobody their privacy.
 *
 * A certificate that *does* parse and is expired is the reader's own and is
 * challenged: they hold a certificate for this installation, so its existence
 * is not news to them.
 */
enum MtlsRejection: string
{
    // ------------------------------------------------------- operator faults

    /**
     * 🛑 `docup.edge.trusted_proxies` is empty, `*` or `private`, so no
     * assertion can be trusted precisely enough to mean anything.
     *
     * Probe-only: {@see EdgeAssertion::from()} already yields nothing from an
     * untrusted peer, so this case exists to refuse **activation** of a binding
     * that would believe anybody who can reach the port rather than to refuse a
     * request.
     */
    case TerminatorNotPinned = 'mtls.terminator_not_pinned';

    /** No `docup.auth.client_certificate.header` is configured. */
    case HeaderNotConfigured = 'mtls.header_not_configured';

    /**
     * The configured header name is one DocUp will not read.
     *
     * 🛑 §8.9.4's class. {@see EdgeAssertion::mayRead()} admits only `X-…`
     * names and refuses every spelling of the host — so a configuration that
     * named one yields null rather than a subject, and this is how an operator
     * finds out instead of wondering why nobody authenticates.
     */
    case HeaderNotReadable = 'mtls.header_not_readable';

    /**
     * The header's value is not a certificate in the declared format.
     *
     * See the class note: this is **not** a rejected credential.
     */
    case Unparseable = 'mtls.unparseable';

    /**
     * 🛑 The subject attribute appears more than once in the certificate.
     *
     * Refused rather than resolved, by the same reasoning §8.12.18 applies to
     * SAML's "exactly one Assertion" and `LdapRejection::SubjectAmbiguous` to a
     * filter matching two entries: picking the first would authenticate
     * whichever attribute OpenSSL happened to order first.
     */
    case SubjectAmbiguous = 'mtls.subject_ambiguous';

    /** The certificate carries no value for the configured subject attribute. */
    case SubjectMissing = 'mtls.subject_missing';

    // --------------------------------------------------------- reader faults

    /**
     * 🛑 The terminator's own verdict on the handshake was not success.
     *
     * The single most important case here, because it is the **only** proof
     * DocUp can ever have that the handshake happened at all. A certificate is
     * a public document: anybody can copy one and anybody can forward it.
     * Possession is proven by the private key, in the handshake, which PHP
     * never sees. See {@see MtlsDriver}'s class note on what this driver can
     * and cannot establish.
     */
    case HandshakeNotVouched = 'mtls.handshake_not_vouched';

    /** `notAfter` is in the past. */
    case Expired = 'mtls.expired';

    /** `notBefore` is in the future — a clock skew or a pre-issued certificate. */
    case NotYetValid = 'mtls.not_yet_valid';

    /**
     * Whether this failure is the operator's to fix, which decides whether
     * §8.12.19's degraded 503 or §8.12.23's `deny_status` is owed.
     */
    public function isOperatorFault(): bool
    {
        return match ($this) {
            self::HandshakeNotVouched,
            self::Expired,
            self::NotYetValid => false,
            default => true,
        };
    }

    /**
     * 🛑 Whether a reader presented something that was refused, which is the
     * only thing permitting §8.12.23's 401.
     *
     * Deliberately **narrower** than `! isOperatorFault()`: a handshake the
     * terminator declined to vouch for may mean the reader offered no
     * certificate at all, and "offered nothing" is not "presented and
     * rejected". {@see MtlsDriver} distinguishes the two from the verdict's own
     * text, because nginx says `NONE` for the first and `FAILED:<reason>` for
     * the second.
     */
    public function isRejectedCredential(): bool
    {
        return match ($this) {
            self::Expired,
            self::NotYetValid => true,
            default => false,
        };
    }

    /** The audit action this refusal is recorded under (§8.22.4's dotted names). */
    public function auditAction(): string
    {
        return $this->value.'.refused';
    }

    /**
     * What an **operator** is told, on §8.12.19's health page.
     *
     * 🛑 Never what a reader is told. A reader gets §8.12.23's `deny_status`
     * and an empty body; these sentences name headers, formats and the
     * installation's proxy configuration.
     */
    public function explain(): string
    {
        return match ($this) {
            self::TerminatorNotPinned => 'An asserted identity needs a terminator named by '
                .'address. Set `DOCUP_TRUSTED_PROXIES` to the proxy\'s address or CIDR: `*` and '
                .'`private` trust a shape of peer rather than a peer, and an identity trusted by '
                .'shape is one anybody of that shape can assert.',
            self::HeaderNotConfigured => 'Set `DOCUP_CLIENT_CERTIFICATE_HEADER` to the header the '
                .'terminator forwards the certificate in. Nothing is read until you do.',
            self::HeaderNotReadable => 'DocUp reads only `X-…` header names, and never one that '
                .'names a host or a path (§8.9.4). Rename the header at the terminator.',
            self::Unparseable => 'The header held something that is not a certificate in the '
                .'declared format. Check `DOCUP_CLIENT_CERTIFICATE_FORMAT` against the '
                .'terminator: nginx\'s `$ssl_client_escaped_cert` is `escaped_pem` and Caddy\'s '
                .'`…certificate_der_base64` is `der_base64`.',
            self::SubjectAmbiguous => 'The certificate carries that attribute more than once, so '
                .'the subject is not unique. DocUp refuses rather than choosing one.',
            self::SubjectMissing => 'The certificate carries no value for the configured subject '
                .'attribute.',
            self::HandshakeNotVouched => 'The terminator did not vouch for the handshake. This is '
                .'the only proof that the reader holds the private key, so DocUp refuses without '
                .'it.',
            self::Expired => 'The certificate has expired.',
            self::NotYetValid => 'The certificate is not valid yet — check the clocks.',
        };
    }
}
