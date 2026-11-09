<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Mtls;

use App\Auth\Providers\AttemptResult;
use App\Auth\Providers\BindingContext;
use App\Auth\Providers\BindingRefused;
use App\Auth\Providers\BindingRejection;
use App\Auth\Providers\BindingState;
use App\Auth\Providers\DriverRegistry;
use App\Auth\Providers\Drivers\MtlsDriver;
use App\Auth\Providers\EdgeAssertion;
use App\Auth\Providers\Mtls\CertificateFormat;
use App\Auth\Providers\Mtls\ClientCertificate;
use App\Auth\Providers\Mtls\MtlsRefused;
use App\Auth\Providers\Mtls\MtlsRejection;
use App\Auth\Providers\ReaderPresentation;
use App\Http\Middleware\TrustEdgeProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Symfony\Component\HttpFoundation\Response;
use Tests\Support\ClientCertificates;
use Tests\TestCase;

/**
 * 🛑 §8.12.17's `mtls`, §8.12.18's "framework-enforced, not driver-optional",
 * and §8.12.4's installation-scope narrowing.
 *
 * Every certificate here is real and minted at run time — see
 * {@see ClientCertificates} for why none is committed and why the binary is
 * used rather than `ext-openssl`.
 *
 * ## 🛑 The two tests to read first
 *
 * {@see self::test_nothing_is_satisfied_without_the_terminators_verdict()} and
 * {@see self::test_an_impostor_ca_with_the_same_dn_is_refused_only_by_the_verdict()}
 * are the pair that justifies the driver's shape. A certificate is a public
 * document and its issuer DN is a field the signer wrote, so an attacker can
 * mint one that claims any issuer. The terminator's verdict on the handshake is
 * the only thing that distinguishes a reader who holds the private key from a
 * reader who holds a copy of somebody's certificate — which is why the verdict
 * header is mandatory rather than recommended, and why nginx's
 * `ssl_verify_client optional` (which forwards certificates it **rejected**)
 * would otherwise be a complete bypass.
 */
final class MtlsBoundaryTest extends TestCase
{
    private const string PROXY = '172.20.0.9';

    private const string TRUSTED = '172.20.0.0/16';

    private const string CERT_HEADER = 'X-Client-Cert';

    private const string VERDICT_HEADER = 'X-Client-Verify';

    protected function setUp(): void
    {
        parent::setUp();

        /* A correctly-configured installation; each test narrows from here. */
        Config::set('docup.edge.trusted_proxies', self::TRUSTED);
        Config::set('docup.auth.client_certificate.header', self::CERT_HEADER);
        Config::set('docup.auth.client_certificate.format', 'escaped_pem');
        Config::set('docup.auth.client_certificate.verdict_header', self::VERDICT_HEADER);
        Config::set('docup.auth.client_certificate.verdict_success', 'SUCCESS');
    }

    // ------------------------------------------------- the parsing boundary

    /** nginx's `$ssl_client_escaped_cert`, which is the spelling to prefer. */
    public function test_it_parses_escaped_pem_from_nginx(): void
    {
        $pem = ClientCertificates::leaf();

        $certificate = ClientCertificate::parse(
            ClientCertificates::asEscapedPem($pem),
            CertificateFormat::EscapedPem,
        );

        $this->assertSame('alice', $certificate->commonName);
        $this->assertSame(ClientCertificates::fingerprintOf($pem), $certificate->fingerprint);
    }

    /** Caddy's and HAProxy's spelling. */
    public function test_it_parses_base64_der_from_caddy(): void
    {
        $pem = ClientCertificates::leaf();

        $certificate = ClientCertificate::parse(
            ClientCertificates::asDerBase64($pem),
            CertificateFormat::DerBase64,
        );

        $this->assertSame(ClientCertificates::fingerprintOf($pem), $certificate->fingerprint);
    }

    /**
     * 🛑 PEM whose newlines became whitespace, which is what a terminator's
     * header folding does to `$ssl_client_cert`.
     *
     * Three manglings of the same certificate must produce the same
     * fingerprint, because the alternative is one reader in a deployment whose
     * proxy folds differently.
     */
    public function test_it_parses_pem_whose_newlines_became_whitespace(): void
    {
        $pem = ClientCertificates::leaf();
        $expected = ClientCertificates::fingerprintOf($pem);

        foreach (["\t", ' ', "\n\t"] as $replacement) {
            $this->assertSame(
                $expected,
                ClientCertificate::parse(
                    str_replace("\n", $replacement, $pem),
                    CertificateFormat::Pem,
                )->fingerprint,
                'a terminator folding newlines into '.json_encode($replacement).' changed the certificate',
            );
        }
    }

    public function test_it_refuses_something_that_is_not_a_certificate(): void
    {
        foreach (['not a certificate', '', 'AAAA', str_repeat('A', 200)] as $junk) {
            try {
                ClientCertificate::parse($junk, CertificateFormat::Pem);
                $this->fail('parsed '.json_encode($junk));
            } catch (MtlsRefused $refused) {
                $this->assertSame(MtlsRejection::Unparseable, $refused->rejection);
            }
        }
    }

    /**
     * 🛑 A ceiling, applied before OpenSSL sees the value.
     *
     * Without it the only bound would be the terminator's header limit, which
     * is the operator's configuration rather than DocUp's.
     */
    public function test_it_refuses_a_value_over_the_ceiling(): void
    {
        $this->expectException(MtlsRefused::class);

        ClientCertificate::parse(str_repeat('A', 16_385), CertificateFormat::DerBase64);
    }

    /**
     * 🛑 Two `CN` attributes are a refusal, not a choice.
     *
     * OpenSSL reports a repeated attribute as an **array**, so a driver reading
     * it as a string would compare the literal `"Array"` against a configured
     * suffix. Picking the first would authenticate whichever of two people
     * OpenSSL happened to order first.
     */
    public function test_it_refuses_a_subject_attribute_that_appears_twice(): void
    {
        $this->expectException(MtlsRefused::class);

        ClientCertificate::parse(
            ClientCertificates::twoCommonNames(),
            CertificateFormat::Pem,
        );
    }

    /**
     * 🛑 The issuer matches whatever order the operator wrote it in.
     *
     * `openssl x509 -noout -issuer`, a Windows CA console and a proxy log print
     * the same DN three ways. A string comparison would refuse a correct
     * configuration, and the symptom — "nobody can read anything" — is one an
     * operator fixes by loosening whatever they can reach.
     */
    public function test_the_issuer_matches_in_any_attribute_order_or_spacing(): void
    {
        $certificate = ClientCertificate::parse(ClientCertificates::leaf(), CertificateFormat::Pem);

        $spellings = [
            'C=GB, O=DocUp Test, CN=DocUp Test Issuing CA',
            'CN=DocUp Test Issuing CA,O=DocUp Test,C=GB',
            'cn=docup test issuing ca, o=docup test, c=gb',
            '  O=DocUp Test ,  C=GB ,CN=DocUp Test Issuing CA  ',
        ];

        foreach ($spellings as $spelling) {
            $this->assertTrue(
                $certificate->issuerMatches($spelling),
                'the operator wrote the issuer as "'.$spelling.'" and it did not match',
            );
        }

        $this->assertFalse($certificate->issuerMatches('CN=Somebody Else Root,O=Somebody Else,C=GB'));
    }

    /**
     * 🛑 An unparseable configured DN matches **nothing**.
     *
     * The difference between a gate that is wrong and a gate that is absent. A
     * `return true` here — or a normalisation that collapsed to the empty
     * string on both sides — would make a typo in the field into "accept every
     * certificate authority on earth".
     */
    public function test_an_unparseable_issuer_dn_matches_nothing(): void
    {
        $certificate = ClientCertificate::parse(ClientCertificates::leaf(), CertificateFormat::Pem);

        foreach (['', '   ', 'DocUp Test Issuing CA', '=nothing', ',,,'] as $nonsense) {
            $this->assertFalse(
                $certificate->issuerMatches($nonsense),
                json_encode($nonsense).' matched an issuer',
            );
        }
    }

    /**
     * 🛑 The validity window is refused in **both** directions.
     *
     * Driven through `assertCurrent()`'s own clock parameter rather than by
     * minting a skewed certificate, so both branches are deterministic. The
     * driver's mapping of each to §8.12.23 is asserted separately, with real
     * expired and future certificates.
     */
    public function test_the_validity_window_is_refused_in_both_directions(): void
    {
        $certificate = ClientCertificate::parse(ClientCertificates::leaf(), CertificateFormat::Pem);

        /* Inside the window: no exception. */
        $certificate->assertCurrent($certificate->validFrom + 1);

        try {
            $certificate->assertCurrent($certificate->validTo + 1);
            $this->fail('an expired certificate was accepted');
        } catch (MtlsRefused $refused) {
            $this->assertSame(MtlsRejection::Expired, $refused->rejection);
        }

        try {
            $certificate->assertCurrent($certificate->validFrom - 1);
            $this->fail('a not-yet-valid certificate was accepted');
        } catch (MtlsRefused $refused) {
            $this->assertSame(MtlsRejection::NotYetValid, $refused->rejection);
        }
    }

    /**
     * The email comes from the subject alternative name, which is where RFC
     * 5280 §4.2.1.6 puts it and where every certificate issued this decade has
     * it.
     */
    public function test_the_email_comes_from_the_san(): void
    {
        $certificate = ClientCertificate::parse(ClientCertificates::leaf(), CertificateFormat::Pem);

        $this->assertSame('alice@example.com', $certificate->emailAddress);
        $this->assertSame('alice@example.com', $certificate->subjectValue('email'));
    }

    /** And from the subject DN when a legacy CA put it there. */
    public function test_the_email_comes_from_the_subject_dn_too(): void
    {
        $certificate = ClientCertificate::parse(
            ClientCertificates::leafWithEmailInTheDn(),
            CertificateFormat::Pem,
        );

        $this->assertSame('alice@example.com', $certificate->subjectValue('email'));
    }

    public function test_a_missing_subject_attribute_is_a_refusal(): void
    {
        $certificate = ClientCertificate::parse(ClientCertificates::leaf(), CertificateFormat::Pem);

        $this->expectException(MtlsRefused::class);

        $certificate->subjectValue('organisational_unit_we_never_support');
    }

    // ------------------------------------------------ configuration refusals

    public function test_it_needs_an_issuer_dn(): void
    {
        $this->refuses(['subject_attribute' => 'common_name'], 'issuer_dn');
    }

    public function test_it_refuses_an_issuer_dn_that_is_not_a_dn(): void
    {
        /*
         * 🛑 Refused at write time, not at probe time. An unparseable DN
         * matches nothing, so the binding would activate and deny everybody
         * with no clue why — and the operator is still looking at the field
         * now.
         */
        $this->refuses(
            ['issuer_dn' => 'DocUp Test Issuing CA', 'subject_attribute' => 'common_name'],
            'attribute=value',
        );
    }

    public function test_it_needs_a_known_subject_attribute(): void
    {
        $this->refuses(
            ['issuer_dn' => ClientCertificates::ISSUER_DN, 'subject_attribute' => 'serial'],
            'subject_attribute',
        );
    }

    /**
     * 🛑 A fingerprint is normalised from the four spellings operators actually
     * copy.
     *
     * `openssl` uses upper-case with colons, a browser uses upper-case with
     * spaces, a Windows console omits separators and `sha256sum` is lower-case.
     * Refusing a correct fingerprint for its punctuation would be a binding
     * that admits nobody for a cosmetic reason.
     */
    public function test_it_normalises_fingerprints_from_every_spelling(): void
    {
        $bare = ClientCertificates::fingerprintOf(ClientCertificates::leaf());
        $colons = implode(':', str_split(strtoupper($bare), 2));

        $config = (new MtlsDriver)->validate([
            'issuer_dn' => ClientCertificates::ISSUER_DN,
            'subject_attribute' => 'common_name',
            'fingerprints' => [$bare, $colons, strtoupper($bare), str_replace(':', ' ', $colons)],
        ]);

        /* All four are the same fingerprint, so one survives. */
        $this->assertSame(['fingerprints' => [$bare]], ['fingerprints' => $config['fingerprints'] ?? []]);
    }

    /**
     * 🛑 SHA-1 is refused rather than accepted-and-never-matched.
     *
     * A 40-character fingerprint would pass a looser check and then never
     * equal a SHA-256 one, so the binding would deny everybody. And SHA-1
     * collisions are practical (SHAttered, 2017), so a pin on one is not a pin.
     */
    public function test_it_refuses_a_sha1_fingerprint(): void
    {
        $this->refuses([
            'issuer_dn' => ClientCertificates::ISSUER_DN,
            'subject_attribute' => 'common_name',
            'fingerprints' => [str_repeat('ab', 20)],
        ], 'SHA-256');
    }

    public function test_it_caps_the_fingerprint_list(): void
    {
        $this->refuses([
            'issuer_dn' => ClientCertificates::ISSUER_DN,
            'subject_attribute' => 'common_name',
            'fingerprints' => array_fill(0, 501, str_repeat('ab', 32)),
        ], 'at most');
    }

    // ------------------------------------------------------ scope and capability

    /**
     * 🛑 §8.12.4: "`ldap`, `mtls` and `header_trust` MUST be
     * **installation-scope only**."
     */
    public function test_it_is_installation_scope_only(): void
    {
        foreach (['installation', 'organisation'] as $scope) {
            $this->assertInstanceOf(MtlsDriver::class, DriverRegistry::permittedAt('mtls', $scope));
        }

        try {
            DriverRegistry::permittedAt('mtls', 'project');
            $this->fail('a project configured mtls');
        } catch (BindingRefused $refused) {
            $this->assertSame(BindingRejection::ScopeNotPermitted, $refused->rejection);
        }
    }

    /**
     * No dashboard role from a certificate, where `ldap` says yes — a
     * certificate's `OU` is a string a CA operator typed once at issuance.
     */
    public function test_it_maps_no_dashboard_roles(): void
    {
        $this->assertFalse(MtlsDriver::mayMapDashboardRoles());
    }

    // --------------------------------------------------------------- the probe

    /**
     * 🛑 `*` and `private` are refused, and this is the probe's most important
     * refusal after the verdict header.
     *
     * {@see TrustEdgeProxies} accepts both, and for `ip_allowlist` that is a
     * reasonable convenience — the worst outcome is a gate that narrows
     * nothing. Here the worst outcome is anybody who can reach the port
     * asserting any identity, because with `*` every peer is "the address
     * directly in front".
     */
    public function test_the_probe_fails_unless_the_terminator_is_pinned_by_address(): void
    {
        foreach (['', '*', 'private', 'PRIVATE', ' * '] as $loose) {
            Config::set('docup.edge.trusted_proxies', $loose);

            $this->assertFalse(
                (new MtlsDriver)->probe($this->binding())->passed,
                'the probe passed with trusted_proxies = '.json_encode($loose),
            );
        }

        Config::set('docup.edge.trusted_proxies', self::TRUSTED);

        $this->assertTrue((new MtlsDriver)->probe($this->binding())->passed);
    }

    public function test_the_probe_fails_without_a_certificate_header(): void
    {
        Config::set('docup.auth.client_certificate.header', '');

        $this->assertFalse((new MtlsDriver)->probe($this->binding())->passed);
    }

    /**
     * 🛑 §8.9.4's class, as a probe refusal.
     *
     * {@see EdgeAssertion::mayRead()} admits only `X-…` names and refuses every
     * spelling of the host, so a configuration naming one reads nothing — and
     * this is how an operator finds out instead of wondering why nobody
     * authenticates.
     */
    public function test_the_probe_fails_on_a_header_name_docup_will_not_read(): void
    {
        foreach (['Host', 'X-Forwarded-Host', 'X-Original-Host', 'Forwarded', 'Authorization'] as $name) {
            Config::set('docup.auth.client_certificate.header', $name);

            $this->assertFalse(
                (new MtlsDriver)->probe($this->binding())->passed,
                $name.' was accepted as a certificate header',
            );
        }
    }

    /**
     * 🛑 **The bypass.** No verdict header, no activation.
     *
     * nginx's `ssl_verify_client optional` forwards
     * `$ssl_client_escaped_cert` **even when verification failed**. A driver
     * reading only the certificate would accept a self-signed one an attacker
     * minted with `issuer=CN=DocUp Test Issuing CA`, because the issuer DN is a
     * field in a document the attacker wrote. §8.12.19 forbids leaving
     * `verifying` until a probe passes, so this is the right place to refuse:
     * the binding never activates.
     */
    public function test_the_probe_fails_without_a_verdict_header(): void
    {
        foreach (['', 'Host', 'X-Forwarded-Host'] as $name) {
            Config::set('docup.auth.client_certificate.verdict_header', $name);

            $result = (new MtlsDriver)->probe($this->binding());

            $this->assertFalse($result->passed, json_encode($name).' was accepted as a verdict header');
            $this->assertStringContainsString('REFUSED', $result->summary);
        }
    }

    public function test_the_probe_passes_on_a_configured_installation(): void
    {
        $result = (new MtlsDriver)->probe($this->binding());

        $this->assertTrue($result->passed);
        $this->assertStringContainsString('escaped_pem', $result->summary);
        $this->assertStringContainsString(self::VERDICT_HEADER, $result->summary);
    }

    // ------------------------------------------------------------- the attempt

    /**
     * 🛑 A forged certificate header from a direct client asserts **nothing**.
     *
     * Not refused by the driver — never built. {@see EdgeAssertion::from()}
     * returns {@see EdgeAssertion::none()} for an untrusted peer, so there is
     * no object that could hold the forgery.
     */
    public function test_an_untrusted_peer_asserts_nothing(): void
    {
        $result = $this->drive(
            certificate: ClientCertificates::leaf(),
            verdict: 'SUCCESS',
            peer: '198.51.100.7',
        );

        $this->assertFalse($result->satisfied);
        $this->assertFalse($result->credentialRejected);
    }

    public function test_a_certificate_from_a_trusted_hop_satisfies_the_binding(): void
    {
        $result = $this->drive(ClientCertificates::leaf(), 'SUCCESS');

        $this->assertTrue($result->satisfied);
        $this->assertNotNull($result->subject);
    }

    /**
     * 🛑 **Nothing is satisfied without the terminator's verdict**, however
     * good the certificate is.
     *
     * The invariant the whole driver rests on. A binding activated before the
     * verdict header was configured authenticates nobody rather than everybody.
     */
    public function test_nothing_is_satisfied_without_the_terminators_verdict(): void
    {
        Config::set('docup.auth.client_certificate.verdict_header', '');

        $result = $this->drive(ClientCertificates::leaf(), 'SUCCESS');

        $this->assertFalse($result->satisfied);
        $this->assertFalse($result->credentialRejected);
    }

    /**
     * 🛑 An impostor CA that spells its DN **identically** is refused only by
     * the verdict, and that is the honest statement of what this driver can do.
     *
     * The issuer DN is a field in a document the signer wrote, so the pin
     * cannot tell a real CA from a forgery. What it can do — and the other half
     * of this test proves — is refuse a certificate from a *different* CA that
     * the terminator trusted by mistake.
     */
    public function test_an_impostor_ca_with_the_same_dn_is_refused_only_by_the_verdict(): void
    {
        /* The forgery is accepted when the terminator vouches for it. */
        $this->assertTrue(
            $this->drive(ClientCertificates::leafFromAnImpostorCa(), 'SUCCESS')->satisfied,
            'the issuer DN pin cannot detect a forgery; only the handshake can',
        );

        /* And refused when it does not. */
        $this->assertFalse(
            $this->drive(ClientCertificates::leafFromAnImpostorCa(), 'FAILED:self signed certificate')->satisfied,
        );

        /*
         * 🛑 And the half the pin DOES buy: a terminator misconfigured to trust
         * a second CA still fails DocUp's issuer check, even with a verdict of
         * SUCCESS.
         */
        $other = $this->drive(ClientCertificates::leafFromAnotherIssuer(), 'SUCCESS');

        $this->assertFalse($other->satisfied);
        $this->assertFalse(
            $other->credentialRejected,
            'a certificate from another binding\'s CA must not challenge: see the ordering comment',
        );
    }

    /** `FAILED:<reason>` means a certificate was presented and refused. */
    public function test_a_failed_verdict_is_a_rejected_credential(): void
    {
        $result = $this->drive(ClientCertificates::leaf(), 'FAILED:unable to get local issuer certificate');

        $this->assertFalse($result->satisfied);
        $this->assertTrue($result->credentialRejected);
    }

    /**
     * 🛑 `NONE` means the reader offered nothing, which is **not** §8.12.23's
     * "presented and rejected".
     *
     * A terminator forwards the verdict on every request, so treating `NONE` as
     * a rejected credential would challenge every anonymous reader on the
     * installation.
     */
    public function test_no_certificate_offered_is_not_a_rejected_credential(): void
    {
        foreach (['NONE', 'none', ' None '] as $verdict) {
            $result = $this->drive(ClientCertificates::leaf(), $verdict);

            $this->assertFalse($result->satisfied);
            $this->assertFalse($result->credentialRejected, $verdict.' challenged the reader');
        }
    }

    /** An expired certificate is the reader's own, and they should renew it. */
    public function test_an_expired_certificate_is_a_rejected_credential(): void
    {
        $result = $this->drive(ClientCertificates::expiredLeaf(), 'SUCCESS');

        $this->assertFalse($result->satisfied);
        $this->assertTrue($result->credentialRejected);
    }

    public function test_a_not_yet_valid_certificate_is_a_rejected_credential(): void
    {
        $result = $this->drive(ClientCertificates::futureLeaf(), 'SUCCESS');

        $this->assertFalse($result->satisfied);
        $this->assertTrue($result->credentialRejected);
    }

    /**
     * 🛑 **An unparseable certificate is NOT a rejected credential**, and this
     * is the test that keeps one environment-variable typo from becoming an
     * existence oracle for every private project.
     *
     * The terminator forwards the header on every request. If `format` is
     * wrong, every value fails to parse — so classifying that as "presented and
     * rejected" would turn every private 404 on the installation into a 401.
     */
    public function test_an_unparseable_certificate_is_not_a_rejected_credential(): void
    {
        /* The format is wrong for the value: DER base64 read as escaped PEM. */
        Config::set('docup.auth.client_certificate.format', 'der_base64');

        $result = $this->drive(ClientCertificates::asEscapedPem(ClientCertificates::leaf()), 'SUCCESS', raw: true);

        $this->assertFalse($result->satisfied);
        $this->assertFalse(
            $result->credentialRejected,
            '🛑 a format misconfiguration must not challenge: it would make every private 404 a 401',
        );
    }

    /** A pinned fingerprint list narrows to exactly those certificates. */
    public function test_a_pinned_fingerprint_list_narrows_to_it(): void
    {
        $leaf = ClientCertificates::leaf();

        $this->assertTrue($this->drive($leaf, 'SUCCESS', config: [
            'fingerprints' => [ClientCertificates::fingerprintOf($leaf)],
        ])->satisfied);

        $this->assertFalse($this->drive($leaf, 'SUCCESS', config: [
            'fingerprints' => [str_repeat('ab', 32)],
        ])->satisfied);
    }

    /** A subject suffix narrows the audience, case-insensitively. */
    public function test_a_subject_suffix_narrows_the_audience(): void
    {
        $leaf = ClientCertificates::leaf();

        $this->assertTrue($this->drive($leaf, 'SUCCESS', config: [
            'subject_attribute' => 'email',
            'subject_suffix' => '@example.com',
        ])->satisfied);

        $this->assertFalse($this->drive($leaf, 'SUCCESS', config: [
            'subject_attribute' => 'email',
            'subject_suffix' => '@elsewhere.test',
        ])->satisfied);
    }

    /**
     * 🛑 The subject never leaves the driver as an email address.
     *
     * §8.12.1 forbids email "for linking or lookup", and an `AttemptResult`'s
     * subject travels into the reader's grant token — a cookie is both.
     */
    public function test_the_subject_never_leaves_the_driver_as_an_email(): void
    {
        $result = $this->drive(ClientCertificates::leaf(), 'SUCCESS', config: [
            'subject_attribute' => 'email',
        ]);

        $this->assertTrue($result->satisfied);
        $this->assertNotNull($result->subject);
        $this->assertStringNotContainsString('alice', $result->subject);
        $this->assertStringNotContainsString('@', $result->subject);
        $this->assertStringStartsWith('mtls:', $result->subject);
    }

    /**
     * 🛑 A header that arrived **twice** is refused outright.
     *
     * `header_up +X-Foo` appends rather than replaces, and a terminator that
     * sets the header only for an authenticated reader passes an
     * unauthenticated reader's own value straight through. Either way DocUp
     * would see two values — the operator's and an attacker's — and taking the
     * first is choosing between them on the strength of whichever proxy
     * ordered them.
     */
    public function test_a_duplicated_certificate_header_is_refused_outright(): void
    {
        $edge = $this->edge([
            self::CERT_HEADER => [
                ClientCertificates::asEscapedPem(ClientCertificates::leaf()),
                ClientCertificates::asEscapedPem(ClientCertificates::leafFromAnotherIssuer()),
            ],
            self::VERDICT_HEADER => 'SUCCESS',
        ]);

        $this->assertNull($edge->clientCertificate, 'two values were resolved to one');

        $result = (new MtlsDriver)->attempt(
            $this->binding(),
            new ReaderPresentation(edge: $edge),
        );

        $this->assertFalse($result->satisfied);
    }

    /**
     * 🛑 And a duplicated **verdict** header is refused too, which is the same
     * attack aimed at the one fact that matters.
     *
     * Without this, a client could append `SUCCESS` to a terminator's
     * `FAILED:…` and have DocUp read whichever came first.
     */
    public function test_a_duplicated_verdict_header_is_refused_outright(): void
    {
        $edge = $this->edge([
            self::CERT_HEADER => ClientCertificates::asEscapedPem(ClientCertificates::leaf()),
            self::VERDICT_HEADER => ['SUCCESS', 'FAILED:forged'],
        ]);

        $this->assertNull($edge->certificateVerdict);
        $this->assertFalse((new MtlsDriver)->attempt(
            $this->binding(),
            new ReaderPresentation(edge: $edge),
        )->satisfied);
    }

    // ------------------------------------------------------------- fixtures

    /**
     * One attempt, driven through the real request path.
     *
     * 🛑 Through {@see EdgeAssertion::from()} rather than by constructing an
     * assertion, because the constructor is private and that is the point: a
     * test that could build an assertion without a trusted hop would be testing
     * a driver nobody can reach.
     *
     * @param  array<string, mixed>  $config  overrides for the binding
     */
    private function drive(
        string $certificate,
        ?string $verdict,
        string $peer = self::PROXY,
        array $config = [],
        bool $raw = false,
    ): AttemptResult {
        $headers = [
            self::CERT_HEADER => $raw ? $certificate : ClientCertificates::asEscapedPem($certificate),
        ];

        if ($verdict !== null) {
            $headers[self::VERDICT_HEADER] = $verdict;
        }

        return (new MtlsDriver)->attempt(
            $this->binding($config),
            new ReaderPresentation(edge: $this->edge($headers, $peer)),
        );
    }

    /**
     * @param  array<string, string|list<string>>  $headers
     */
    private function edge(array $headers, string $peer = self::PROXY): EdgeAssertion
    {
        $request = Request::create('https://docs.example.test/x', 'GET', [], [], [], [
            'REMOTE_ADDR' => $peer,
        ]);

        foreach ($headers as $name => $value) {
            foreach (is_array($value) ? $value : [$value] as $index => $one) {
                /* `false` appends, which is how a duplicated header is built. */
                $request->headers->set($name, $one, $index === 0);
            }
        }

        (new TrustEdgeProxies)->handle($request, static fn (): Response => new Response);

        return EdgeAssertion::from($request);
    }

    /** @param  array<string, mixed>  $overrides */
    private function binding(array $overrides = []): BindingContext
    {
        return new BindingContext(
            id: str_repeat("\x2a", 16),
            type: 'mtls',
            name: 'Corporate certificates',
            config: array_merge([
                'issuer_dn' => ClientCertificates::ISSUER_DN,
                'subject_attribute' => 'common_name',
            ], $overrides),
            state: BindingState::Active,
        );
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private function refuses(array $config, string $expected): void
    {
        try {
            (new MtlsDriver)->validate($config);
            $this->fail('accepted '.json_encode($config));
        } catch (BindingRefused $refused) {
            $this->assertSame(BindingRejection::ConfigInvalid, $refused->rejection);
            $this->assertStringContainsString($expected, $refused->getMessage());
        }
    }
}
