<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Support;

use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * 🛑 §9.4's malicious SAML responses, in PHP, with **real signatures**.
 *
 * ## Why this file exists at all
 *
 * `tests/Fixtures/AbuseCorpus/saml/build_saml.py` was written in Phase 00 and
 * cannot run where it matters — neither the application container nor CI has a
 * Python interpreter, which is the same discovery Phase 03 recorded for the
 * archive builders and resolved with `tests/Support/HostileArchives.php`. This
 * is that file for SAML, and `corpus.json`'s `builder` names are its method
 * names.
 *
 * ## 🛑 And why it signs for real
 *
 * Phase 00's builder says so itself:
 *
 * > "These are NOT cryptographically valid signatures — a real signature cannot
 * > be forged here and does not need to be. Each fixture isolates one
 * > *structural* validation failure… The cryptographic cases (a genuinely valid
 * > signature over a tampered body) require a signing key and are added in
 * > **Phase 25**."
 *
 * That is the brief, and it names the one case that cannot be faked:
 * **signature wrapping**. A wrapped response has a signature that verifies
 * *perfectly* over an element the service provider is not reading. A fixture
 * with an invalid signature cannot test it, because the signature check fails
 * first and the wrapping is never reached — the test would pass against a
 * service provider with no wrapping defence at all.
 *
 * So this class generates a key pair per instance, signs the legitimate
 * elements properly with `xmlseclibs`, and then tampers. The attack is real.
 *
 * 🛑 The key is generated in memory and never written to disk, so nothing here
 * is a committed secret.
 *
 * ## The base response is a fixture too
 *
 * {@see self::valid()} must be **accepted**. Every hostile builder starts from
 * it and changes one thing, which is what makes each case about that one thing
 * — and a corpus with no accepted case passes equally well against a validator
 * that refuses everything.
 */
final class HostileSamlResponses
{
    public const string PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

    public const string ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /** Where DocUp's assertion consumer service lives, for `Destination`. */
    public const string ACS = 'https://docup.localhost/_/auth/saml/acs';

    /** DocUp's own entity id, for `Audience`. */
    public const string AUDIENCE = 'https://docup.localhost/saml/metadata';

    public const string ISSUER = 'https://idp.example.test/realms/acme';

    public const string SUBJECT = 'reader-at-acme';

    /**
     * The private key as **PEM**, not as an `OpenSSLAsymmetricKey`.
     *
     * 🛑 `XMLSecurityKey::loadKey()` requires a string in 4.0.1 — its
     * `signData()` throws `Key is not loaded` on anything else, from a line that
     * mentions neither the type nor the caller. Found the honest way.
     */
    private string $privateKeyPem;

    private string $certificate;

    public function __construct()
    {
        /*
         * A self-signed certificate, because a SAML signature is verified
         * against the certificate the operator configured on the binding —
         * there is no chain to validate and no CA involved. §8.12.18 says
         * nothing about chains for the same reason.
         */
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);

        if ($key === false) {
            throw new \RuntimeException('openssl could not generate a test key');
        }

        $pem = '';

        if (openssl_pkey_export($key, $pem) === false) {
            throw new \RuntimeException('openssl could not export the test private key');
        }

        $this->privateKeyPem = $pem;

        $csr = openssl_csr_new(['commonName' => 'idp.example.test'], $key, ['digest_alg' => 'sha256']);

        /*
         * `openssl_csr_new` returns `true` when it also generated the key pair
         * in place, which is not the case here but is in its signature — so the
         * narrowing is explicit rather than a `=== false` check that leaves
         * `true` in the type.
         */
        if (! $csr instanceof \OpenSSLCertificateSigningRequest) {
            throw new \RuntimeException('openssl could not generate a test CSR');
        }

        $signed = openssl_csr_sign($csr, null, $key, 365, ['digest_alg' => 'sha256']);

        if ($signed === false) {
            throw new \RuntimeException('openssl could not sign the test certificate');
        }

        $certificate = '';
        openssl_x509_export($signed, $certificate);

        $this->certificate = $certificate;
    }

    /** The certificate an operator would configure on the binding. */
    public function certificate(): string
    {
        return $this->certificate;
    }

    /** The certificate as the bare base64 body, which is how SAML carries it. */
    public function certificateBody(): string
    {
        $body = preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $this->certificate);

        return is_string($body) ? $body : '';
    }

    // ------------------------------------------------------- the base case

    /**
     * 🛑 A response that **must be accepted**, and every builder's starting
     * point.
     *
     * Signed on the Response *and* on the Assertion, which is what §8.12.18
     * requires: "signature required on Response **and** Assertion".
     *
     * @param  array<string, string>  $overrides  element text to replace
     */
    public function valid(
        ?string $requestId = 'docup-request-1',
        ?int $now = null,
        array $overrides = [],
        string $assertionId = 'assertion-1',
    ): string {
        $xml = $this->skeleton($requestId, $now, $overrides, $assertionId);

        $xml = $this->signAssertion($xml, $assertionId);

        return $this->signResponse($xml);
    }

    // ----------------------------------------- §17's seven, and the rest

    /** `saml-001`: no signature anywhere. */
    public function unsigned(?string $requestId = 'docup-request-1'): string
    {
        return $this->skeleton($requestId);
    }

    /**
     * `saml-002`: the Response is signed and the Assertion is not.
     *
     * 🛑 The case that makes §8.12.18's "**and**" load-bearing. A service
     * provider that accepted either signature alone would accept this — and the
     * assertion, which carries every claim, would be unsigned.
     */
    public function response_signed_assertion_unsigned(?string $requestId = 'docup-request-1'): string
    {
        return $this->signResponse($this->skeleton($requestId));
    }

    /**
     * 🛑 `saml-003`: XML signature wrapping, with a **genuinely valid**
     * signature.
     *
     * The attack, concretely: take a legitimately signed assertion, move it
     * somewhere the service provider does not read from, and put a forged
     * assertion where the service provider *does* read. The signature still
     * verifies — over the decoy. A service provider that asks "is this document
     * signed" gets `yes` and then reads the attacker's claims.
     *
     * Here the real signed assertion is hidden inside the Response's
     * `<Extensions>`, and an unsigned forged assertion carrying a different
     * `NameID` takes its place as the Response's child.
     *
     * 🛑 The defence is not "check the signature". It is resolving the signed
     * reference to an element **by identity** and requiring it to be the
     * element whose claims are about to be read —
     * `App\Auth\Providers\Saml\SignatureVerifier`.
     */
    public function signature_wrapping(?string $requestId = 'docup-request-1'): string
    {
        $now = time();

        /* A legitimately signed assertion, for the real subject. */
        $genuine = $this->signAssertion($this->skeleton($requestId, $now), 'assertion-1');

        $document = new \DOMDocument;
        $document->loadXML($genuine);

        $response = $document->documentElement;

        if ($response === null) {
            throw new \RuntimeException('the skeleton did not parse');
        }

        $signedAssertion = $response->getElementsByTagNameNS(self::ASSERTION, 'Assertion')->item(0);

        if (! $signedAssertion instanceof \DOMElement) {
            throw new \RuntimeException('no assertion to wrap');
        }

        /*
         * 🛑 The forged assertion takes the signed one's **place**, and the
         * signed one is moved into `<Extensions>` — still present, still
         * verifying, and no longer where the claims are read from.
         */
        $forged = $this->assertionElement($document, $requestId, $now, [
            'NameID' => 'attacker@evil.test',
        ], 'assertion-forged');

        $extensions = $document->createElementNS(self::PROTOCOL, 'samlp:Extensions');

        $response->insertBefore($extensions, $signedAssertion);
        $response->replaceChild($forged, $signedAssertion);
        $extensions->appendChild($signedAssertion);

        return $this->signResponse((string) $document->saveXML());
    }

    /**
     * 🛑 The **other** XSW variant: the read element carries a signature, and
     * that signature references somebody else.
     *
     * {@see self::signature_wrapping()} hides the real signed assertion and
     * leaves an *unsigned* forgery in its place — which DocUp refuses as
     * `SignatureMissing`, because the element it would read claims from has no
     * signature of its own.
     *
     * This one is the harder shape, and the reason `SignatureWrapped` exists as
     * a separate case: the forged assertion carries a genuine
     * `<ds:Signature>`, copied whole from the real one, so a verifier that
     * finds "a signature on this element" finds one — and it verifies, over
     * the real assertion, which is still in the document. Only resolving the
     * reference and comparing it to the element being read catches it.
     *
     * Both variants must be refused and their audit events differ, because the
     * attacks differ: one strips a signature, the other misdirects it.
     */
    public function signature_wrapping_reference(?string $requestId = 'docup-request-1'): string
    {
        $now = time();

        $genuine = $this->signAssertion($this->skeleton($requestId, $now), 'assertion-1');

        $document = new \DOMDocument;
        $document->loadXML($genuine);

        $response = $document->documentElement;

        if ($response === null) {
            throw new \RuntimeException('the skeleton did not parse');
        }

        $signed = $response->getElementsByTagNameNS(self::ASSERTION, 'Assertion')->item(0);

        if (! $signed instanceof \DOMElement) {
            throw new \RuntimeException('no assertion to wrap');
        }

        $signature = null;

        foreach ($signed->childNodes as $child) {
            if ($child instanceof \DOMElement && $child->localName === 'Signature') {
                $signature = $child;
                break;
            }
        }

        if ($signature === null) {
            throw new \RuntimeException('the genuine assertion is unsigned');
        }

        /*
         * The forgery, carrying a **copy** of the real signature — which still
         * references `assertion-1`, not `assertion-forged`.
         */
        $forged = $this->assertionElement($document, $requestId, $now, [
            'NameID' => 'attacker@evil.test',
        ], 'assertion-forged');

        $forged->appendChild($signature->cloneNode(true));

        /*
         * The real assertion is moved into `<Extensions>` so it is still
         * present for the reference to resolve to, and the forgery takes its
         * place as the Response's child.
         */
        $extensions = $document->createElementNS(self::PROTOCOL, 'samlp:Extensions');

        $response->insertBefore($extensions, $signed);
        $response->replaceChild($forged, $signed);
        $extensions->appendChild($signed);

        return $this->signResponse((string) $document->saveXML());
    }

    /**
     * `saml-004`: an HMAC "signature".
     *
     * 🛑 XML-DSig's algorithm registry includes `hmac-sha1` and friends, which
     * is the SAML equivalent of JWT's `alg: none` problem: an HMAC signature
     * means the verification key is a shared secret, so anybody holding it can
     * mint. Written by hand because a signing library will not produce one
     * against an RSA key.
     */
    public function alg_none(?string $requestId = 'docup-request-1'): string
    {
        $xml = $this->signAssertion($this->skeleton($requestId), 'assertion-1');

        return str_replace(
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            'http://www.w3.org/2000/09/xmldsig#hmac-sha1',
            $this->signResponse($xml),
        );
    }

    /** `saml-005`: two Assertions, both properly signed. */
    public function two_assertions(?string $requestId = 'docup-request-1'): string
    {
        $now = time();

        $xml = $this->signAssertion($this->skeleton($requestId, $now), 'assertion-1');

        $document = new \DOMDocument;
        $document->loadXML($xml);

        $response = $document->documentElement;

        if ($response === null) {
            throw new \RuntimeException('the skeleton did not parse');
        }

        /*
         * 🛑 A **second** assertion, also signed, for a different subject. The
         * ambiguity is the attack: a service provider that reads "the"
         * assertion has to pick one, and an attacker who can add a second gets
         * to influence which.
         */
        $second = $this->assertionElement($document, $requestId, $now, [
            'NameID' => 'attacker@evil.test',
        ], 'assertion-2');

        $response->appendChild($second);

        return $this->signResponse((string) $document->saveXML());
    }

    /** `saml-006`: `Audience` names another service provider. */
    public function wrong_audience(?string $requestId = 'docup-request-1'): string
    {
        return $this->valid($requestId, overrides: ['Audience' => 'https://other-sp.example.test/saml/metadata']);
    }

    /** `saml-007`: `Destination` is another service provider's ACS. */
    public function wrong_destination(?string $requestId = 'docup-request-1'): string
    {
        return $this->valid($requestId, overrides: ['Destination' => 'https://evil.test/_/auth/saml/acs']);
    }

    /** `saml-008`: `NotOnOrAfter` is in the past. */
    public function expired_notonorafter(?string $requestId = 'docup-request-1'): string
    {
        return $this->valid($requestId, now: time() - 3600);
    }

    /**
     * `saml-009`: the replay.
     *
     * 🛑 Returns a **valid** response, because a replay is not a malformed
     * document — it is the *same* document a second time. The case is
     * behavioural: present this twice and the second must be refused, which is
     * what the assertion-id cache is for. A builder cannot express that alone,
     * and the test that drives it says so.
     */
    public function replayed_assertion_id(?string $requestId = 'docup-request-1'): string
    {
        return $this->valid($requestId, assertionId: 'assertion-replayed');
    }

    /**
     * 🛑 `saml-010`: comment truncation (CVE-2017-11427's family).
     *
     * `<NameID>reader-at-acme<!--x-->@evil.test</NameID>`. Canonicalisation —
     * which the signature was computed over — strips the comment and joins the
     * text, so the signature covers `reader-at-acme@evil.test`. A naive reader
     * calling `textContent` gets the same string. But a reader that takes the
     * **first text node** gets `reader-at-acme`, and several products did
     * exactly that, turning one identity into another.
     *
     * 🛑 The comment is inserted **after** signing, so the signature is over
     * the document as it stands — which is the whole point: the attack needs a
     * valid signature.
     */
    public function comment_truncation(?string $requestId = 'docup-request-1'): string
    {
        $xml = $this->valid($requestId, overrides: ['NameID' => self::SUBJECT.'@evil.test']);

        /*
         * Inserted textually, after signing, so no library gets a chance to
         * canonicalise it away before it reaches the validator.
         */
        return str_replace(
            '>'.self::SUBJECT.'@evil.test<',
            '>'.self::SUBJECT.'<!--x-->@evil.test<',
            $xml,
        );
    }

    /**
     * 🛑 `saml-011`: XXE, which must never reach an entity-expanding parser.
     *
     * Both halves: an **external** entity reading a local file, and an
     * **internal** one (the billion-laughs shape) that needs no network at all
     * — because "external entity loading is off by default in libxml 2.9+" is
     * true and answers only half the problem.
     */
    public function xxe_external_entity(?string $requestId = 'docup-request-1'): string
    {
        $body = $this->skeleton($requestId);

        $doctype = '<!DOCTYPE samlp:Response ['
            .'<!ENTITY xxe SYSTEM "file:///etc/passwd">'
            .']>';

        return str_replace('<?xml version="1.0"?>', '<?xml version="1.0"?>'.$doctype, $body)
            ? str_replace(
                '>'.self::SUBJECT.'<',
                '>&xxe;<',
                str_replace('<?xml version="1.0"?>', '<?xml version="1.0"?>'.$doctype, $body),
            )
            : $body;
    }

    /** The internal-entity half: no network, just expansion. */
    public function xxe_billion_laughs(?string $requestId = 'docup-request-1'): string
    {
        $doctype = '<!DOCTYPE samlp:Response ['
            .'<!ENTITY a "aaaaaaaaaa">'
            .'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
            .'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
            .']>';

        $body = $this->skeleton($requestId);

        return str_replace(
            '>'.self::SUBJECT.'<',
            '>&c;<',
            str_replace('<?xml version="1.0"?>', '<?xml version="1.0"?>'.$doctype, $body),
        );
    }

    /**
     * `saml-012`: an `EncryptedAssertion` with no signature over it.
     *
     * 🛑 The content is not really encrypted, and does not need to be: §8.12.18
     * refuses an encrypted assertion without a signature, and that refusal must
     * happen **before** any decryption — so a fixture that decrypted to
     * something would be testing a path DocUp must never take.
     */
    public function encrypted_unsigned(?string $requestId = 'docup-request-1'): string
    {
        $xml = $this->skeleton($requestId);

        $document = new \DOMDocument;
        $document->loadXML($xml);

        $response = $document->documentElement;
        $assertion = $response?->getElementsByTagNameNS(self::ASSERTION, 'Assertion')->item(0);

        if ($response === null || ! $assertion instanceof \DOMElement) {
            throw new \RuntimeException('the skeleton did not parse');
        }

        $encrypted = $document->createElementNS(self::ASSERTION, 'saml:EncryptedAssertion');
        $data = $document->createElementNS('http://www.w3.org/2001/04/xmlenc#', 'xenc:EncryptedData');
        $cipher = $document->createElementNS('http://www.w3.org/2001/04/xmlenc#', 'xenc:CipherData');
        $value = $document->createElementNS('http://www.w3.org/2001/04/xmlenc#', 'xenc:CipherValue');

        $value->appendChild($document->createTextNode(base64_encode('not really encrypted')));
        $cipher->appendChild($value);
        $data->appendChild($cipher);
        $encrypted->appendChild($data);

        $response->replaceChild($encrypted, $assertion);

        return (string) $document->saveXML();
    }

    /**
     * `saml-013`: IdP-initiated — no `InResponseTo` at all.
     *
     * 🛑 §8.12.18: "IdP-initiated off by default". A response DocUp did not ask
     * for is a response DocUp cannot tie to a reader's session, and accepting
     * one means anybody who can make an IdP emit an assertion can log somebody
     * in. Properly signed here, because the signature is not the problem.
     */
    public function idp_initiated(): string
    {
        return $this->valid(requestId: null);
    }

    /**
     * `saml-014`: 130 seconds of skew, against §8.12.18's 120-second ceiling.
     *
     * 🛑 Shifted by **160**, not 130, and the arithmetic is the point. The
     * skeleton sets `NotBefore` to `now - 30`, so shifting the clock by 130
     * puts `NotBefore` only 100 seconds in the future — comfortably inside the
     * ceiling, and the validator accepted it. The first version of this builder
     * did exactly that, and the test caught the **fixture**: a ceiling only
     * holds if something is genuinely on the far side of it.
     *
     * 160 - 30 = 130, so `NotBefore` lands exactly 130 seconds ahead.
     */
    public function clock_skew_130s(?string $requestId = 'docup-request-1'): string
    {
        return $this->valid($requestId, now: time() + self::MAX_SKEW_OVERSHOOT + 30);
    }

    /**
     * 🛑 How far past §8.12.18's 120-second ceiling `clock_skew_130s` reaches.
     *
     * A named constant so the fixture's intent survives a change to the
     * skeleton's own offsets — which is how the first version went wrong.
     */
    public const int MAX_SKEW_OVERSHOOT = 130;

    // ------------------------------------------------------------ building

    /**
     * An unsigned response, complete and well-formed.
     *
     * @param  array<string, string>  $overrides
     */
    private function skeleton(
        ?string $requestId = 'docup-request-1',
        ?int $now = null,
        array $overrides = [],
        string $assertionId = 'assertion-1',
    ): string {
        $now ??= time();

        $document = new \DOMDocument('1.0');

        $response = $document->createElementNS(self::PROTOCOL, 'samlp:Response');
        $document->appendChild($response);

        $response->setAttribute('ID', 'response-1');
        $response->setAttribute('Version', '2.0');
        $response->setAttribute('IssueInstant', self::instant($now));
        $response->setAttribute('Destination', $overrides['Destination'] ?? self::ACS);

        if ($requestId !== null) {
            $response->setAttribute('InResponseTo', $requestId);
        }

        /*
         * 🛑 `setIdAttribute` so `getElementById` resolves `ID` without a DTD.
         * Without it, xmlseclibs' reference resolution cannot find the element
         * by its URI — and a DTD is exactly what SafeXml refuses.
         */
        $response->setIdAttribute('ID', true);

        $issuer = $document->createElementNS(self::ASSERTION, 'saml:Issuer');
        $issuer->appendChild($document->createTextNode($overrides['Issuer'] ?? self::ISSUER));
        $response->appendChild($issuer);

        $status = $document->createElementNS(self::PROTOCOL, 'samlp:Status');
        $code = $document->createElementNS(self::PROTOCOL, 'samlp:StatusCode');
        $code->setAttribute('Value', $overrides['StatusCode'] ?? 'urn:oasis:names:tc:SAML:2.0:status:Success');
        $status->appendChild($code);
        $response->appendChild($status);

        $response->appendChild($this->assertionElement($document, $requestId, $now, $overrides, $assertionId));

        return (string) $document->saveXML();
    }

    /**
     * One `<Assertion>`, as an element so a builder can place it.
     *
     * @param  array<string, string>  $overrides
     */
    private function assertionElement(
        \DOMDocument $document,
        ?string $requestId,
        int $now,
        array $overrides = [],
        string $id = 'assertion-1',
    ): \DOMElement {
        $assertion = $document->createElementNS(self::ASSERTION, 'saml:Assertion');

        $assertion->setAttribute('ID', $id);
        $assertion->setAttribute('Version', '2.0');
        $assertion->setAttribute('IssueInstant', self::instant($now));
        $assertion->setIdAttribute('ID', true);

        $issuer = $document->createElementNS(self::ASSERTION, 'saml:Issuer');
        $issuer->appendChild($document->createTextNode($overrides['Issuer'] ?? self::ISSUER));
        $assertion->appendChild($issuer);

        $subject = $document->createElementNS(self::ASSERTION, 'saml:Subject');
        $nameId = $document->createElementNS(self::ASSERTION, 'saml:NameID');
        $nameId->setAttribute('Format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent');
        $nameId->appendChild($document->createTextNode($overrides['NameID'] ?? self::SUBJECT));
        $subject->appendChild($nameId);

        $confirmation = $document->createElementNS(self::ASSERTION, 'saml:SubjectConfirmation');
        $confirmation->setAttribute('Method', 'urn:oasis:names:tc:SAML:2.0:cm:bearer');

        $confirmationData = $document->createElementNS(self::ASSERTION, 'saml:SubjectConfirmationData');
        $confirmationData->setAttribute('NotOnOrAfter', self::instant($now + 300));
        $confirmationData->setAttribute('Recipient', $overrides['Destination'] ?? self::ACS);

        if ($requestId !== null) {
            $confirmationData->setAttribute('InResponseTo', $requestId);
        }

        $confirmation->appendChild($confirmationData);
        $subject->appendChild($confirmation);
        $assertion->appendChild($subject);

        $conditions = $document->createElementNS(self::ASSERTION, 'saml:Conditions');
        $conditions->setAttribute('NotBefore', self::instant($now - 30));
        $conditions->setAttribute('NotOnOrAfter', self::instant($now + 300));

        $restriction = $document->createElementNS(self::ASSERTION, 'saml:AudienceRestriction');
        $audience = $document->createElementNS(self::ASSERTION, 'saml:Audience');
        $audience->appendChild($document->createTextNode($overrides['Audience'] ?? self::AUDIENCE));
        $restriction->appendChild($audience);
        $conditions->appendChild($restriction);
        $assertion->appendChild($conditions);

        $statement = $document->createElementNS(self::ASSERTION, 'saml:AuthnStatement');
        $statement->setAttribute('AuthnInstant', self::instant($now));
        $assertion->appendChild($statement);

        return $assertion;
    }

    /** Sign the Assertion in place, properly. */
    private function signAssertion(string $xml, string $assertionId): string
    {
        $document = new \DOMDocument;
        $document->loadXML($xml);

        $assertion = $document->getElementsByTagNameNS(self::ASSERTION, 'Assertion')->item(0);

        if (! $assertion instanceof \DOMElement) {
            throw new \RuntimeException('no assertion to sign');
        }

        $this->signElement($document, $assertion, $assertionId);

        return (string) $document->saveXML();
    }

    /** Sign the Response in place, properly. */
    private function signResponse(string $xml): string
    {
        $document = new \DOMDocument;
        $document->loadXML($xml);

        $response = $document->documentElement;

        if ($response === null) {
            throw new \RuntimeException('no response to sign');
        }

        $this->signElement($document, $response, 'response-1');

        return (string) $document->saveXML();
    }

    /**
     * One enveloped XML-DSig signature over one element.
     *
     * 🛑 `insertSignature` places the signature as the element's **first**
     * child after `<Issuer>`, which is where the SAML schema requires it. A
     * signature appended at the end is schema-invalid and some verifiers refuse
     * it, which would make every fixture fail for the wrong reason.
     */
    private function signElement(\DOMDocument $document, \DOMElement $element, string $id): void
    {
        $dsig = new XMLSecurityDSig;
        $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

        $dsig->addReference(
            $element,
            XMLSecurityDSig::SHA256,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N],
            ['id_name' => 'ID', 'overwrite' => false, 'force_uri' => true],
        );

        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
        $key->loadKey($this->privateKeyPem);

        $dsig->sign($key);
        $dsig->add509Cert($this->certificate);

        /*
         * After `<Issuer>` when there is one, which is the schema's order
         * (`Issuer`, `Signature`, …) — and `insertSignature`'s second argument
         * is the node to insert before.
         */
        $issuer = null;

        foreach ($element->childNodes as $child) {
            if ($child instanceof \DOMElement && $child->localName === 'Issuer') {
                $issuer = $child->nextSibling;
                break;
            }
        }

        $dsig->insertSignature($element, $issuer);

        unset($id);
    }

    /** SAML's instant format: UTC, ISO 8601, no fractional seconds. */
    private static function instant(int $at): string
    {
        return gmdate('Y-m-d\TH:i:s\Z', $at);
    }
}
