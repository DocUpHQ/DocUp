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
use App\Auth\Providers\EdgeAssertion;
use App\Auth\Providers\Federation\ReaderSubject;
use App\Auth\Providers\Mtls\CertificateFormat;
use App\Auth\Providers\Mtls\ClientCertificate;
use App\Auth\Providers\Mtls\MtlsRefused;
use App\Auth\Providers\Mtls\MtlsRejection;
use App\Auth\Providers\ProbeResult;
use App\Auth\Providers\ReaderPresentation;

/**
 * 🛑 §8.12.17's `mtls`: a client certificate the TLS terminator verified,
 * forwarded to an application that never terminates TLS.
 *
 * Tenth registry entry, §8.12.4's second installation-scope-only driver, and
 * the same shape P24, P25 and the `ldap` driver established: the driver
 * conducts no protocol. Everything §8.12.18 would call protocol lives in
 * `App\Auth\Providers\Mtls` behind `final` classes with no options.
 *
 * ## 🛑 What this driver can prove, and the one thing it cannot
 *
 * **A certificate is a public document.** Possession of the private key is what
 * identifies a reader, and that proof exists only inside the TLS handshake,
 * which happens at the terminator (§11.3 — PHP never terminates TLS). PHP sees
 * a header.
 *
 * So this driver requires **two independent things**, and the second is the
 * one operators get wrong:
 *
 * 1. The certificate's own content checks out: the issuer is the one this
 *    binding pinned, it is inside its validity window, and its fingerprint is
 *    in the allowlist where one is configured.
 * 2. 🛑 The terminator **vouched for the handshake**, in its own verdict
 *    header. Without that, (1) is worthless — and not marginally so.
 *
 * ### 🛑 Why the verdict header is mandatory rather than recommended
 *
 * nginx's `ssl_verify_client optional` forwards `$ssl_client_escaped_cert`
 * **even when verification failed**, setting `$ssl_client_verify` to
 * `FAILED:<reason>`. A driver that read only the certificate would therefore
 * accept a **self-signed certificate an attacker minted** with
 * `issuer=CN=Corp Issuing CA` — the issuer DN is a field in a document the
 * attacker wrote. That is a complete authentication bypass reachable from one
 * reasonable-looking line of nginx configuration.
 *
 * So {@see self::probe()} **fails** when no verdict header is configured, and
 * {@see self::attempt()} is never satisfied without one. The cost is one line
 * at the terminator and it is in the operator documentation:
 *
 * - nginx: `proxy_set_header X-Client-Verify $ssl_client_verify;`
 * - Caddy, inside a `require_and_verify` route:
 *   `header_up X-Client-Verify SUCCESS`
 *
 * ## What this buys over `header_trust`
 *
 * Both are assertions by the terminator, which §8.12.17 marks `header_trust`
 * "yes, by assertion" for. `mtls` asserts the same thing and *also* hands
 * DocUp the certificate, so DocUp can independently refuse a certificate from
 * the wrong CA, one outside its validity window, or one not in a pinned
 * fingerprint list. A terminator misconfigured to trust a second CA still
 * fails DocUp's issuer pin. `header_trust` has no equivalent: a username is
 * either believed or not.
 */
final class MtlsDriver implements AuthComponent
{
    /**
     * 🛑 A cap on the fingerprint allowlist, for the reason
     * {@see IpAllowlistDriver::MAX_RANGES} exists: every entry is compared on
     * every request for every reader on a guarded project.
     *
     * Five hundred pinned certificates is a large fleet of devices and a
     * bounded loop. An operator with more than that wants the issuer pin, which
     * is one comparison regardless of fleet size.
     */
    private const int MAX_FINGERPRINTS = 500;

    /** The two subject attributes a certificate can be asked for. */
    private const array SUBJECT_ATTRIBUTES = ['common_name', 'email'];

    public static function type(): string
    {
        return 'mtls';
    }

    public static function leaf(): AccessLeaf
    {
        return AccessLeaf::Binding;
    }

    /**
     * 🛑 §8.12.4: installation scope only.
     *
     * The requirement's own reason applies literally here — this driver
     * "depends on facts only the TLS terminator can establish", and the
     * terminator belongs to the installation. A project admin configuring it
     * would be pinning an issuer for a handshake they do not control, against
     * a header they cannot see, and the resulting binding would be satisfied or
     * not by the operator's nginx configuration rather than by anything the
     * project decided.
     */
    public static function allowsProjectScope(): bool
    {
        return false;
    }

    /**
     * 🛑 No dashboard roles from a certificate, and `ldap` says yes.
     *
     * The difference is where the group came from. A directory group is a
     * statement by a system whose business is group membership; a certificate's
     * `CN` or `OU` is a string a CA operator typed once at issuance, and a
     * fleet's certificates are frequently issued by a device-management tool
     * with no notion of DocUp's roles at all. Mapping `OU=Admins` to a
     * dashboard role would make certificate issuance a privilege-granting
     * operation nobody designed it to be.
     */
    public static function mayMapDashboardRoles(): bool
    {
        return false;
    }

    /**
     * @param  array<string, mixed>  $config
     * @return array{issuer_dn: string, subject_attribute: string, subject_suffix?: string, fingerprints?: list<string>}
     */
    public function validate(array $config): array
    {
        $issuer = $config['issuer_dn'] ?? null;

        if (! is_string($issuer) || trim($issuer) === '') {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                'mtls needs an `issuer_dn` — the CA whose certificates this binding accepts',
            );
        }

        /*
         * 🛑 Refused at write time if it does not parse, because an
         * unparseable DN matches nothing (see
         * {@see ClientCertificate::issuerMatches()}) and a binding that matches
         * nothing is a binding whose readers all get a 404 with no clue why.
         * §8.12.19's probe would catch the symptom; this catches the cause, in
         * the form where the operator is still looking at the field.
         */
        if (! self::parsesAsDn($issuer)) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '`issuer_dn` must be attribute=value pairs, e.g. "CN=Corp Issuing CA,O=Corp,C=GB"',
            );
        }

        $attribute = $config['subject_attribute'] ?? null;

        if (! is_string($attribute) || ! in_array($attribute, self::SUBJECT_ATTRIBUTES, true)) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '`subject_attribute` must be one of: '.implode(', ', self::SUBJECT_ATTRIBUTES),
            );
        }

        $normalised = [
            'issuer_dn' => trim($issuer),
            'subject_attribute' => $attribute,
        ];

        $suffix = $config['subject_suffix'] ?? null;

        if ($suffix !== null && $suffix !== '') {
            if (! is_string($suffix)) {
                throw BindingRefused::of(BindingRejection::ConfigInvalid, '`subject_suffix` must be a string');
            }

            /*
             * 🛑 Stored lower-cased because it is compared case-insensitively.
             * The stored form and the compared form are the same string, which
             * is the rule {@see IpAllowlistDriver} applies to its ranges and
             * for the same reason: an operator must never see a value in the UI
             * that differs from the one in force.
             */
            $normalised['subject_suffix'] = mb_strtolower(trim($suffix));
        }

        $fingerprints = $config['fingerprints'] ?? null;

        if ($fingerprints !== null && $fingerprints !== []) {
            $normalised['fingerprints'] = self::fingerprints($fingerprints);
        }

        return $normalised;
    }

    /**
     * 🛑 §8.12.19's automated half, and it checks the **installation** rather
     * than the binding.
     *
     * Everything that can make this driver unsafe is installation
     * configuration — the trusted-proxy list, the certificate header, the
     * verdict header — so a probe that only validated the binding's own fields
     * would pass on an installation where the driver cannot work and must not
     * be trusted. §8.12.19 forbids leaving `verifying` until this passes, which
     * makes the probe the right place to refuse: the binding never activates,
     * rather than activating and believing anybody.
     */
    public function probe(BindingContext $binding): ProbeResult
    {
        if (! EdgeAssertion::terminatorIsPinned()) {
            return ProbeResult::fail(MtlsRejection::TerminatorNotPinned->explain());
        }

        $header = config('docup.auth.client_certificate.header');

        if (! is_string($header) || trim($header) === '') {
            return ProbeResult::fail(MtlsRejection::HeaderNotConfigured->explain());
        }

        if (! EdgeAssertion::mayRead($header)) {
            return ProbeResult::fail(MtlsRejection::HeaderNotReadable->explain());
        }

        /*
         * 🛑 The bypass this exists to close is in the class note: nginx's
         * `ssl_verify_client optional` forwards a certificate it **failed** to
         * verify, and the issuer DN is a field the attacker wrote. Without a
         * verdict header there is no proof of the handshake, so the binding
         * must not activate.
         */
        $verdict = config('docup.auth.client_certificate.verdict_header');

        if (! is_string($verdict) || ! EdgeAssertion::mayRead($verdict)) {
            return ProbeResult::fail(
                'No verdict header is configured, and without one a certificate the terminator '
                .'REFUSED is indistinguishable from one it accepted — nginx\'s '
                .'`ssl_verify_client optional` forwards both. Set '
                .'`DOCUP_CLIENT_CERTIFICATE_VERDICT_HEADER`, and at the terminator '
                .'`proxy_set_header X-Client-Verify $ssl_client_verify;` (nginx) or '
                .'`header_up X-Client-Verify SUCCESS` inside a `require_and_verify` route (Caddy).',
            );
        }

        $fingerprints = $binding->strings('fingerprints');

        return ProbeResult::pass(
            'reading '.CertificateFormat::configured()->value.' from '.trim($header)
            .', vouched by '.trim($verdict)
            .', pinned to '.($binding->string('issuer_dn') ?? '?')
            .($fingerprints === null || $fingerprints === []
                ? ''
                : ' and '.count($fingerprints).' pinned certificate(s)'),
        );
    }

    public function attempt(BindingContext $binding, ReaderPresentation $presented): AttemptResult
    {
        $edge = $presented->edge;

        /*
         * 🛑 No assertion, or one that did not arrive through a hop this
         * installation declared its own. {@see EdgeAssertion::from()} has
         * already collapsed the second case to the first, so this is one test
         * rather than two — and a forged certificate header from a direct
         * client cannot reach here in any form.
         */
        if ($edge === null || ! $edge->fromTrustedProxy || $edge->clientCertificate === null) {
            return AttemptResult::unsatisfied();
        }

        $vouched = $this->vouched($edge->certificateVerdict);

        if ($vouched !== null) {
            return $vouched;
        }

        $issuer = $binding->string('issuer_dn');
        $attribute = $binding->string('subject_attribute');

        if ($issuer === null || $attribute === null) {
            /*
             * A binding whose config did not survive — §8.12.19's probe fails
             * for this too, and until then the leaf is simply unsatisfied
             * rather than an error on the serving path.
             */
            return AttemptResult::unsatisfied();
        }

        try {
            $certificate = ClientCertificate::parse(
                $edge->clientCertificate,
                CertificateFormat::configured(),
            );

            /*
             * 🛑 The issuer pin is checked **before** the validity window, and
             * the order is the whole reason a 404 does not become a 401 on an
             * installation with two CAs. A reader whose certificate comes from
             * the other binding's CA must leave this leaf *unsatisfied* — not
             * rejected — whatever else is wrong with their certificate, or the
             * other binding's readers would be challenged by this one.
             */
            if (! $certificate->issuerMatches($issuer)) {
                return AttemptResult::unsatisfied();
            }

            $pinned = $binding->strings('fingerprints');

            if ($pinned !== null && $pinned !== [] && ! self::pinnedHolds($pinned, $certificate->fingerprint)) {
                return AttemptResult::unsatisfied();
            }

            $certificate->assertCurrent(time());

            $value = $certificate->subjectValue($attribute);
        } catch (MtlsRefused $refused) {
            /*
             * 🛑 `rejected()` only for the reader's **own** failures, which
             * {@see MtlsRejection::isRejectedCredential()} narrows to
             * two cases. See that method and
             * {@see MtlsRejection}'s class note: an unparseable
             * certificate is a format misconfiguration that would otherwise
             * turn every private 404 on the installation into a 401.
             */
            return $refused->rejection->isRejectedCredential()
                ? AttemptResult::rejected()
                : AttemptResult::unsatisfied();
        }

        $suffix = $binding->string('subject_suffix');

        if ($suffix !== null && ! str_ends_with(mb_strtolower($value), $suffix)) {
            /*
             * 🛑 Unsatisfied, never rejected. A certificate from the right CA
             * whose subject is outside this binding's audience is somebody
             * else's reader, and challenging them would confirm the project
             * exists.
             */
            return AttemptResult::unsatisfied();
        }

        /*
         * 🛑 The subject is **keyed-hashed here**, in the driver, not left for
         * §20.3 to hash later — because `subject_attribute: email` makes
         * `$value` an email address, and an `AttemptResult`'s subject travels
         * into {@see \App\Access\ReaderContext} and from there into the grant
         * token in the reader's browser. §8.12.1 forbids email "for linking or
         * lookup" and a cookie is both.
         *
         * {@see ReaderSubject::hash()} rather than a bare digest, for its own
         * stated reasons: the key stops enumeration of a small domain, and the
         * binding in the digest stops the same certificate correlating a
         * reader across two organisations.
         */
        return AttemptResult::satisfiedBy(
            AccessLeaf::Binding,
            subject: 'mtls:'.bin2hex(ReaderSubject::hash($binding->id, $value)),
        );
    }

    /**
     * 🛑 The terminator's verdict, or a refusal — never silence.
     *
     * Returns null when the handshake is vouched for and the attempt may
     * continue, and an {@see AttemptResult} when it may not. The three outcomes
     * are deliberately different:
     *
     * - **no verdict header configured, or an unreadable name** → unsatisfied.
     *   The installation has not done the one thing that makes this driver
     *   safe, and the probe says so; failing closed here means a binding
     *   activated before that configuration existed cannot authenticate
     *   anybody.
     * - **`NONE`, or nothing sent** → unsatisfied. The reader offered no
     *   certificate, and "offered nothing" is not §8.12.23's "presented and
     *   rejected": treating it as one would challenge every anonymous reader on
     *   an installation whose terminator forwards the header unconditionally.
     * - **anything else** → rejected. nginx says `FAILED:<reason>`, so the
     *   reader did present a certificate and the terminator refused it. They
     *   hold a certificate for this installation, so a challenge tells them
     *   nothing they did not know.
     */
    private function vouched(?string $verdict): ?AttemptResult
    {
        $header = config('docup.auth.client_certificate.verdict_header');

        if (! is_string($header) || ! EdgeAssertion::mayRead($header)) {
            return AttemptResult::unsatisfied();
        }

        $success = config('docup.auth.client_certificate.verdict_success');
        $success = is_string($success) && $success !== '' ? $success : 'SUCCESS';

        if ($verdict === null || strcasecmp(trim($verdict), 'NONE') === 0) {
            return AttemptResult::unsatisfied();
        }

        /*
         * 🛑 `hash_equals` on a case-folded comparison: the value is not a
         * secret, but it is the single fact that decides whether a forwarded
         * certificate means anything, and a timing-independent comparison here
         * costs nothing and removes the question.
         */
        if (! hash_equals(strtoupper($success), strtoupper(trim($verdict)))) {
            return AttemptResult::rejected();
        }

        return null;
    }

    /**
     * Whether a fingerprint is in the pinned list.
     *
     * 🛑 `hash_equals` in a loop rather than `in_array`, for the reason
     * {@see ReaderTokenDriver} compares digests
     * that way: this decides access, and a short-circuiting string comparison
     * over a list leaks the matching prefix length.
     *
     * @param  list<string>  $pinned
     */
    private static function pinnedHolds(array $pinned, string $fingerprint): bool
    {
        $held = false;

        foreach ($pinned as $one) {
            /*
             * No early return: the loop runs to the end whatever it finds, so
             * the time taken does not depend on the position of the match.
             */
            $held = hash_equals($one, $fingerprint) || $held;
        }

        return $held;
    }

    /**
     * SHA-256 fingerprints, normalised to lower-case hex with no separators.
     *
     * 🛑 Operators copy fingerprints from four places that spell them four
     * ways: `openssl x509 -fingerprint -sha256` uses upper-case with colons, a
     * browser's certificate viewer uses upper-case with spaces, a Windows
     * console omits separators, and `sha256sum` is lower-case. Normalising at
     * write time is what makes the stored form and the compared form the same
     * string; refusing a correct fingerprint for its punctuation would be a
     * binding that admits nobody for a cosmetic reason.
     *
     * @return list<string>
     *
     * @throws BindingRefused
     */
    private static function fingerprints(mixed $fingerprints): array
    {
        if (! is_array($fingerprints)) {
            throw BindingRefused::of(BindingRejection::ConfigInvalid, '`fingerprints` must be a list');
        }

        if (count($fingerprints) > self::MAX_FINGERPRINTS) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                'mtls accepts at most '.self::MAX_FINGERPRINTS.' pinned fingerprints; '
                .'pin the issuer instead for a larger fleet',
            );
        }

        $normalised = [];

        foreach ($fingerprints as $fingerprint) {
            if (! is_string($fingerprint)) {
                throw BindingRefused::of(BindingRejection::ConfigInvalid, 'every fingerprint must be a string');
            }

            $bare = strtolower((string) preg_replace('/[^0-9A-Fa-f]/', '', $fingerprint));

            /*
             * 🛑 SHA-256 only, and the length is how that is enforced. A SHA-1
             * fingerprint is 40 characters and would be accepted by a looser
             * check — then never match, because
             * {@see ClientCertificate::$fingerprint} is SHA-256. SHA-1
             * collisions are practical (SHAttered, 2017), so a pin on one is
             * not a pin.
             */
            if (strlen($bare) !== 64) {
                throw BindingRefused::of(
                    BindingRejection::ConfigInvalid,
                    '"'.$fingerprint.'" is not a SHA-256 fingerprint '
                    .'(64 hex characters; SHA-1 is not accepted, its collisions are practical)',
                );
            }

            $normalised[] = $bare;
        }

        return array_values(array_unique($normalised));
    }

    /**
     * Whether a configured issuer DN is attribute=value pairs.
     *
     * Deliberately lenient about *which* attributes: a CA may legitimately use
     * `DC=`, `serialNumber=` or an OID, and an allowlist of attribute names
     * would refuse a valid configuration. What is checked is the shape, which
     * is what distinguishes a DN from a fingerprint pasted into the wrong
     * field.
     */
    private static function parsesAsDn(string $dn): bool
    {
        $pairs = preg_split('/(?<!\\\\),/', trim($dn)) ?: [];
        $seen = 0;

        foreach ($pairs as $pair) {
            $pair = trim($pair);

            if ($pair === '') {
                continue;
            }

            if (preg_match('/^[A-Za-z0-9.]{1,64}=.+$/', $pair) !== 1) {
                return false;
            }

            $seen++;
        }

        return $seen > 0;
    }
}
