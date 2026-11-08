<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Saml;

use App\Auth\Providers\Saml\SafeXml;
use App\Auth\Providers\Saml\SamlRefused;
use App\Auth\Providers\Saml\SamlRejection;
use App\Auth\Providers\Saml\SignatureVerifier;
use Tests\Support\HostileSamlResponses;
use Tests\TestCase;

/**
 * 🛑 §8.12.18's signature rules, and the one that justifies the design.
 *
 * > "signature required on Response **and** Assertion"
 *
 * The test that matters here is {@see self::test_a_wrapped_signature_is_refused()}.
 * Its fixture carries a **genuinely valid** signature — verified in this file,
 * explicitly, before the refusal is asserted — over an element that is not the
 * one whose claims would be read. A service provider that asks "is this
 * document signed" passes that fixture and is vulnerable.
 *
 * 🛑 Which is why the valid case is asserted first in every test that can:
 * a verifier that refused everything would pass a hostile-input suite
 * perfectly.
 */
final class SignatureVerifierTest extends TestCase
{
    private HostileSamlResponses $idp;

    private SignatureVerifier $verifier;

    protected function setUp(): void
    {
        parent::setUp();

        $this->idp = new HostileSamlResponses;
        $this->verifier = new SignatureVerifier;
    }

    // ------------------------------------------------- the case that works

    /** A properly signed Response and Assertion both verify. */
    public function test_a_valid_signature_verifies_on_both_elements(): void
    {
        $document = SafeXml::parse($this->idp->valid());

        $response = $document->documentElement;

        $this->assertNotNull($response);

        $this->verifier->assertCovers($response, $this->idp->certificate());

        $assertion = SafeXml::child($response, HostileSamlResponses::ASSERTION, 'Assertion');

        $this->assertNotNull($assertion);

        $this->verifier->assertCovers($assertion, $this->idp->certificate());
    }

    // --------------------------------------------- §17's signature cases

    /** 🛑 `saml-001`: a stripped signature. */
    public function test_a_stripped_signature_is_refused(): void
    {
        $this->assertRefusal(
            SamlRejection::SignatureMissing,
            $this->idp->unsigned(),
            fn ($response) => $response,
            '🛑 §8.12.18: a signature is required, not merely checked when present',
        );
    }

    /**
     * 🛑 `saml-002`: the Response is signed and the Assertion is not.
     *
     * The case that makes §8.12.18's "**and**" load-bearing. A verifier that
     * accepted either signature alone would read every claim from an unsigned
     * element.
     */
    public function test_an_unsigned_assertion_under_a_signed_response_is_refused(): void
    {
        $document = SafeXml::parse($this->idp->response_signed_assertion_unsigned());
        $response = $document->documentElement;

        $this->assertNotNull($response);

        /* The Response's own signature is fine. */
        $this->verifier->assertCovers($response, $this->idp->certificate());

        $assertion = SafeXml::child($response, HostileSamlResponses::ASSERTION, 'Assertion');

        $this->assertNotNull($assertion);

        try {
            $this->verifier->assertCovers($assertion, $this->idp->certificate());
            $this->fail('an unsigned assertion verified');
        } catch (SamlRefused $refused) {
            $this->assertSame(SamlRejection::SignatureMissing, $refused->rejection);
        }
    }

    /**
     * 🛑 `saml-003`: signature wrapping, and the fixture's signature is
     * **genuinely valid**.
     *
     * This test proves three things in order, and the order is the argument:
     *
     * 1. the hidden assertion's signature **verifies** — so this is not a
     *    broken document that any verifier would reject;
     * 2. the element a service provider would read from carries **different**
     *    claims;
     * 3. DocUp refuses it as {@see SamlRejection::SignatureWrapped}.
     *
     * Without (1) the test would pass against a verifier with no wrapping
     * defence at all, because the signature check would fail first and the
     * wrapping would never be reached.
     */
    public function test_a_wrapped_signature_is_refused(): void
    {
        $document = SafeXml::parse($this->idp->signature_wrapping());
        $response = $document->documentElement;

        $this->assertNotNull($response);

        /* 1. The genuine signature is hidden in <Extensions> — and it is genuine. */
        $extensions = SafeXml::child($response, HostileSamlResponses::PROTOCOL, 'Extensions');

        $this->assertNotNull($extensions, 'the fixture should hide the signed assertion');

        $hidden = SafeXml::child($extensions, HostileSamlResponses::ASSERTION, 'Assertion');

        $this->assertNotNull($hidden);

        $this->verifier->assertCovers($hidden, $this->idp->certificate());

        /* 2. And the assertion a reader would be admitted by says somebody else. */
        $read = SafeXml::child($response, HostileSamlResponses::ASSERTION, 'Assertion');

        $this->assertNotNull($read);
        $this->assertNotSame(
            $hidden,
            $read,
            'the fixture should put a different assertion where claims are read from',
        );

        $nameId = $read->getElementsByTagNameNS(HostileSamlResponses::ASSERTION, 'NameID')->item(0);

        $this->assertNotNull($nameId);
        $this->assertStringContainsString('evil.test', $nameId->textContent);

        /*
         * 3. 🛑 And DocUp refuses it — because `assertCovers` asks whether a
         * signature covers **this** element, not whether the document is
         * signed.
         *
         * 🛑 As `SignatureMissing`, and that is the honest answer for *this*
         * variant: the attacker stripped the signature from the element DocUp
         * reads and hid it elsewhere, so the element has none. The test first
         * expected `SignatureWrapped` and was wrong — the variant that produces
         * that is the next test, where the forgery carries a copied signature
         * pointing at somebody else.
         */
        try {
            $this->verifier->assertCovers($read, $this->idp->certificate());
            $this->fail('🛑 a wrapped signature was accepted — the claims read were unsigned');
        } catch (SamlRefused $refused) {
            $this->assertSame(
                SamlRejection::SignatureMissing,
                $refused->rejection,
                '🛑 §17: the strip-and-hide variant is refused, with its own event',
            );
        }
    }

    /**
     * 🛑 The harder XSW variant: a signature **is** present on the read
     * element, and it references another one.
     *
     * The case `SignatureWrapped` exists for. The forgery carries a copy of the
     * genuine `<ds:Signature>`, so a verifier that asks "does this element have
     * a signature, and does it verify" gets `yes` twice — the signature is
     * real and the element it covers is still in the document. Only resolving
     * the reference and comparing it to the element being read catches it.
     */
    public function test_a_signature_referencing_another_element_is_refused(): void
    {
        $document = SafeXml::parse($this->idp->signature_wrapping_reference());
        $response = $document->documentElement;

        $this->assertNotNull($response);

        $read = SafeXml::child($response, HostileSamlResponses::ASSERTION, 'Assertion');

        $this->assertNotNull($read);
        $this->assertSame('assertion-forged', $read->getAttribute('ID'));

        /* The element DOES carry a signature — that is what makes this hard. */
        $this->assertNotNull(
            SafeXml::child($read, SignatureVerifier::DSIG, 'Signature'),
            'the fixture should put a signature on the forged assertion',
        );

        /* And the genuine assertion is still present for it to resolve to. */
        $extensions = SafeXml::child($response, HostileSamlResponses::PROTOCOL, 'Extensions');

        $this->assertNotNull($extensions);
        $this->assertNotNull(SafeXml::child($extensions, HostileSamlResponses::ASSERTION, 'Assertion'));

        try {
            $this->verifier->assertCovers($read, $this->idp->certificate());
            $this->fail('🛑 a signature referencing another element was accepted');
        } catch (SamlRefused $refused) {
            $this->assertSame(
                SamlRejection::SignatureWrapped,
                $refused->rejection,
                '🛑 §17: a wrapped signature gets its own audit event',
            );
        }
    }

    /** 🛑 `saml-004`: an HMAC algorithm, which makes the key a shared secret. */
    public function test_a_symmetric_signature_algorithm_is_refused(): void
    {
        $this->assertRefusal(
            SamlRejection::AlgorithmNotAllowed,
            $this->idp->alg_none(),
            fn ($response) => $response,
            '🛑 an HMAC signature means the verification key can mint',
        );
    }

    /**
     * 🛑 A SHA-1 digest is refused even under an allowed signature algorithm.
     *
     * The digest is what the signature actually covers, so checking only
     * `SignatureMethod` is a complete and common miss.
     */
    public function test_a_sha1_digest_is_refused(): void
    {
        $xml = str_replace(
            'http://www.w3.org/2001/04/xmlenc#sha256',
            'http://www.w3.org/2000/09/xmldsig#sha1',
            $this->idp->valid(),
        );

        $this->assertRefusal(
            SamlRejection::AlgorithmNotAllowed,
            $xml,
            fn ($response) => $response,
            '🛑 a signature over a SHA-1 digest is a SHA-1 signature',
        );
    }

    /** A signature made with another key does not verify. */
    public function test_a_signature_from_another_key_is_refused(): void
    {
        $other = new HostileSamlResponses;

        $this->assertRefusal(
            SamlRejection::SignatureInvalid,
            $this->idp->valid(),
            fn ($response) => $response,
            'the certificate decides, and this is the wrong one',
            certificate: $other->certificate(),
        );
    }

    /**
     * 🛑 Tampering after signing is caught by the digest.
     *
     * The ordinary case the whole mechanism exists for, asserted so that a
     * change which accidentally stopped comparing digests would fail here.
     */
    public function test_a_tampered_value_is_refused(): void
    {
        $xml = str_replace(
            '>'.HostileSamlResponses::SUBJECT.'<',
            '>attacker@evil.test<',
            $this->idp->valid(),
        );

        $this->assertRefusal(
            SamlRejection::SignatureInvalid,
            $xml,
            fn ($response) => $response,
            'a value changed after signing must not verify',
        );
    }

    // ---------------------------------------------------------- fixtures

    /**
     * @param  callable(\DOMElement): \DOMElement  $pick  the element to verify
     */
    private function assertRefusal(
        SamlRejection $expected,
        string $xml,
        callable $pick,
        string $because,
        ?string $certificate = null,
    ): void {
        $document = SafeXml::parse($xml);
        $response = $document->documentElement;

        $this->assertNotNull($response);

        try {
            $this->verifier->assertCovers($pick($response), $certificate ?? $this->idp->certificate());
            $this->fail($because.' — but it verified');
        } catch (SamlRefused $refused) {
            $this->assertSame($expected, $refused->rejection, $because);
        }
    }
}
