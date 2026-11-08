<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Saml;

use DOMElement;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * 🛑 One XML-DSig signature, verified over **one named element**.
 *
 * ## The question this class refuses to answer
 *
 * "Is this document signed?" has a useless answer, and asking it is how every
 * signature-wrapping vulnerability happened. A wrapped response *is* signed:
 * the identity provider's real signature is present and verifies perfectly —
 * over an element the service provider is not reading. The service provider
 * asks "is it signed", hears `yes`, and then reads the attacker's claims from
 * somewhere else.
 *
 * So the only question this class answers is: **does a valid signature cover
 * *this* element?** — with "this element" passed in by the caller, who is about
 * to read claims from it.
 *
 * ## 🛑 By node identity, never by id
 *
 * {@see self::covers()} compares `getValidatedNodes()` against the caller's
 * element with `===`, which is PHP object identity. Comparing the `ID`
 * *attribute* instead would be the vulnerability rewritten: an attacker
 * controls every id in the document, so two elements can carry the same one,
 * and the comparison would pass for the wrong element.
 *
 * ## 🛑 And `idKeys`, which is where the XXE defence shows through
 *
 * XML-DSig resolves `URI="#x"` by finding the element whose id attribute is
 * `x`. `xmlseclibs` does that with XPath over a configurable list of attribute
 * names, defaulting to `Id` — and SAML uses `ID`. Without the addition, every
 * reference fails to resolve and every signature "fails" for a reason that has
 * nothing to do with cryptography.
 *
 * The usual alternative is `DOMElement::setIdAttribute()` or a DTD declaring
 * `ID` as an id. Both are unavailable here and deliberately so: {@see SafeXml}
 * refuses any document with a DTD, and that refusal is §17's XXE proof. One
 * defence removing another's usual mechanism is worth saying out loud — the
 * mechanism is replaced, narrowly, rather than the defence being relaxed.
 *
 * 🛑 `xmlseclibs` itself refuses a document where two elements share the
 * referenced id (`Reference URI does not identify a unique node`), which is a
 * defence DocUp gets for free and does not rely on: {@see self::covers()} would
 * refuse the same document anyway, because at most one of those elements can be
 * the caller's.
 */
final readonly class SignatureVerifier
{
    /**
     * 🛑 The signature algorithms DocUp accepts, and nothing extends the list.
     *
     * RSA and ECDSA over SHA-256 and above. What is **excluded** is the
     * interesting half:
     *
     * - **No `hmac-*`.** An HMAC signature on an assertion means the
     *   verification key is a shared secret, so every party holding it can
     *   mint — SAML's version of `alg: none`, and corpus case `saml-004`.
     * - **No SHA-1**, for digests or signatures. Collisions are practical, and
     *   a signature is exactly the place a collision is useful.
     * - **No `dsa-*`.** Nothing issues them and an allowlist entry nothing uses
     *   is an entry nobody tests.
     *
     * @var list<string>
     */
    public const array SIGNATURE_ALGORITHMS = [
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
        'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
        'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
        'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512',
    ];

    /**
     * 🛑 And the digest algorithms, which are a separate decision.
     *
     * A signature over a SHA-1 digest is a SHA-1 signature whatever the
     * signature algorithm says, because the digest is what the signature
     * actually covers. Checking only the signature algorithm is a common and
     * complete miss.
     *
     * @var list<string>
     */
    public const array DIGEST_ALGORITHMS = [
        'http://www.w3.org/2001/04/xmlenc#sha256',
        'http://www.w3.org/2001/04/xmldsig-more#sha384',
        'http://www.w3.org/2001/04/xmlenc#sha512',
    ];

    /** The XML-DSig namespace, for locating a signature by structure. */
    public const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * Assert that a valid signature, made with `$certificate`, covers
     * `$element`.
     *
     * 🛑 The signature must be a **direct child** of the element it covers —
     * an enveloped signature, which is what SAML uses. A signature found
     * anywhere in the subtree would reintroduce the wrapping problem through
     * the search rather than through the comparison.
     *
     * @param  string  $certificate  PEM, from the binding's sealed config
     *
     * @throws SamlRefused
     */
    public function assertCovers(\DOMElement $element, string $certificate): void
    {
        $signature = SafeXml::child($element, self::DSIG, 'Signature');

        if ($signature === null) {
            throw SamlRefused::of(
                SamlRejection::SignatureMissing,
                'no enveloped signature on <'.$element->localName.'>',
            );
        }

        $this->assertAlgorithms($signature);

        $dsig = new XMLSecurityDSig;

        /*
         * 🛑 See the class note: SAML's id attribute is `ID` and xmlseclibs
         * defaults to `Id`, and the DTD that would normally declare it is
         * refused by SafeXml as §17's XXE proof.
         */
        $dsig->idKeys[] = 'ID';

        if ($dsig->locateSignature($element) === null) {
            throw SamlRefused::of(
                SamlRejection::SignatureMissing,
                'the signature on <'.$element->localName.'> is not locatable',
            );
        }

        /*
         * 🛑 **The reference is checked against this element BEFORE the
         * signature is verified**, and the ordering is what makes the two
         * refusals distinguishable.
         *
         * `xmlseclibs::validateReference()` only ever **throws** — it has no
         * false return — and it throws the same way for two very different
         * facts: a reference that resolves to nothing or to several nodes
         * (wrapping), and a reference that resolves fine but whose digest does
         * not match (tampering). An earlier version caught the exception and
         * called everything `SignatureWrapped`, which made a tampered value
         * report an attack it was not. §17 wants distinct audit events, and an
         * operator reading "wrapped" for a clock-skewed proxy rewriting a byte
         * would chase the wrong thing entirely.
         *
         * So DocUp resolves the reference itself, first. After that, the only
         * thing left for `validateReference()` to fail on is the digest.
         */
        $this->assertReferenceNames($signature, $element);

        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'public']);

        try {
            $key->loadKey($certificate, false, true);
        } catch (\Throwable $e) {
            throw SamlRefused::of(
                SamlRejection::ConfigInvalid,
                'the binding\'s certificate is not a usable X.509 certificate',
            );
        }

        /*
         * 🛑 The cryptographic check, and the one thing in this phase that is
         * not DocUp's own code. Canonicalisation and digest comparison are
         * where the subtle failures live, so they are delegated to a library
         * whose only job is XML-DSig — while every *structural* decision stays
         * here, which is what §8.12.18's "framework-enforced" requires.
         */
        try {
            $dsig->canonicalizeSignedInfo();

            /*
             * The digest, now that the reference is known to name this element:
             * a failure here is a document changed after signing.
             */
            $dsig->validateReference();
        } catch (\Throwable $e) {
            throw SamlRefused::of(
                SamlRejection::SignatureInvalid,
                'the signed digest does not match <'.$element->localName.'>',
            );
        }

        if ($this->check($dsig, $key) !== 1) {
            throw SamlRefused::of(
                SamlRejection::SignatureInvalid,
                'the signature on <'.$element->localName.'> does not verify',
            );
        }

        $this->assertValidatedNodeIs($dsig, $element);
    }

    /**
     * 🛑 The signature's one reference names **this** element.
     *
     * The first half of the wrapping defence, and the half that gives the
     * refusal its name. An enveloped SAML signature references its own parent
     * by `URI="#<ID>"`, so a signature whose reference points anywhere else is
     * a signature about another element — which is XML signature wrapping in
     * its purest form: the attacker keeps a real signature and points it at a
     * decoy.
     *
     * 🛑 This compares **id strings**, which the attacker writes — so it is
     * not the security boundary. It is the *classification* boundary: it makes
     * "wrapped" distinguishable from "tampered" before the digest is checked.
     * The security boundary is {@see self::assertValidatedNodeIs()}, which
     * compares node **identity** after verification, and both must pass.
     *
     * @throws SamlRefused
     */
    private function assertReferenceNames(\DOMElement $signature, \DOMElement $element): void
    {
        $signedInfo = SafeXml::child($signature, self::DSIG, 'SignedInfo');

        if ($signedInfo === null) {
            throw SamlRefused::of(SamlRejection::ResponseMalformed, 'the signature has no <SignedInfo>');
        }

        $references = SafeXml::children($signedInfo, self::DSIG, 'Reference');

        /* The count is already checked by assertAlgorithms(); narrowed here. */
        if (count($references) !== 1) {
            throw SamlRefused::of(
                SamlRejection::SignatureWrapped,
                'the signature carries '.count($references).' references; exactly one is required',
            );
        }

        $uri = $references[0]->getAttribute('URI');
        $id = $element->getAttribute('ID');

        if ($id === '') {
            throw SamlRefused::of(
                SamlRejection::ResponseMalformed,
                '<'.$element->localName.'> carries no ID for a signature to reference',
            );
        }

        /*
         * 🛑 An empty URI means "the whole document", which for an enveloped
         * signature on a child element is not the same thing as this element —
         * and accepting it would mean trusting an element because its *parent*
         * was signed. Refused rather than resolved.
         */
        if (! hash_equals('#'.$id, $uri)) {
            throw SamlRefused::of(
                SamlRejection::SignatureWrapped,
                'the signature references `'.$uri.'`, not this <'.$element->localName.'>',
            );
        }
    }

    /**
     * 🛑 **The wrapping defence**: the signature covered this element and only
     * this element.
     *
     * @throws SamlRefused
     */
    private function assertValidatedNodeIs(XMLSecurityDSig $dsig, \DOMElement $element): void
    {
        $validated = $dsig->getValidatedNodes();

        if ($validated === null || count($validated) !== 1) {
            throw SamlRefused::of(
                SamlRejection::SignatureWrapped,
                'the signature covers '.($validated === null ? 'nothing' : (string) count($validated))
                .' nodes; exactly one is required',
            );
        }

        /*
         * An **array**, not a `DOMNodeList` — `getValidatedNodes()` is annotated
         * `array<int|string, DOMNode>|null`, and its keys are the reference
         * ids rather than integers, so the one element is taken by
         * `array_values` rather than by `[0]`.
         */
        $covered = array_values($validated)[0];

        /*
         * 🛑 `!==` on the objects, which is identity. Comparing ids would be
         * the vulnerability rewritten: an attacker writes every id in the
         * document, so an id comparison can pass for an element nobody signed.
         */
        if ($covered !== $element) {
            throw SamlRefused::of(
                SamlRejection::SignatureWrapped,
                'the signature covers <'.($covered instanceof \DOMElement ? $covered->localName : 'other')
                .'>, not the <'.$element->localName.'> whose claims would be read',
            );
        }
    }

    /**
     * The algorithm allowlist, over both the signature and the digest.
     *
     * @throws SamlRefused
     */
    private function assertAlgorithms(\DOMElement $signature): void
    {
        $signedInfo = SafeXml::child($signature, self::DSIG, 'SignedInfo');

        if ($signedInfo === null) {
            throw SamlRefused::of(SamlRejection::ResponseMalformed, 'the signature has no <SignedInfo>');
        }

        $method = SafeXml::child($signedInfo, self::DSIG, 'SignatureMethod');
        $algorithm = $method?->getAttribute('Algorithm') ?? '';

        if (! in_array($algorithm, self::SIGNATURE_ALGORITHMS, true)) {
            throw SamlRefused::of(
                SamlRejection::AlgorithmNotAllowed,
                'the signature declares `'.$algorithm.'`',
            );
        }

        /*
         * 🛑 And every reference's digest. A signature over a SHA-1 digest is a
         * SHA-1 signature whatever `SignatureMethod` says, because the digest
         * is what the signature actually covers — checking only the signature
         * algorithm is a complete and common miss.
         */
        $references = SafeXml::children($signedInfo, self::DSIG, 'Reference');

        if ($references === []) {
            throw SamlRefused::of(SamlRejection::ResponseMalformed, 'the signature references nothing');
        }

        if (count($references) !== 1) {
            /*
             * One reference, because this is an enveloped signature over one
             * element. Several would make "what did it cover" a question with
             * several answers, which is the wrapping problem's shape.
             */
            throw SamlRefused::of(
                SamlRejection::SignatureWrapped,
                'the signature carries '.count($references).' references; exactly one is required',
            );
        }

        foreach ($references as $reference) {
            $digest = SafeXml::child($reference, self::DSIG, 'DigestMethod');
            $digestAlgorithm = $digest?->getAttribute('Algorithm') ?? '';

            if (! in_array($digestAlgorithm, self::DIGEST_ALGORITHMS, true)) {
                throw SamlRefused::of(
                    SamlRejection::AlgorithmNotAllowed,
                    'the signature digests with `'.$digestAlgorithm.'`',
                );
            }
        }
    }

    /**
     * The library's own signature check.
     *
     * 🛑 Wrapped in a method of its own so the cryptographic call has one call
     * site, which is the shape every other verifier in this codebase has:
     * `GrantVerifier` and `IdTokenVerifier` both keep the primitive
     * behind one method and own the decisions around it.
     */
    private function check(XMLSecurityDSig $dsig, XMLSecurityKey $key): int
    {
        try {
            return (int) $dsig->verify($key);
        } catch (\Throwable $e) {
            return 0;
        }
    }
}
