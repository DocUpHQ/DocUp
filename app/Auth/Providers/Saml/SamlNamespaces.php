<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Saml;

/**
 * The SAML 2.0 namespace URIs, in one place.
 *
 * 🛑 **Constants rather than literals, because every lookup in this namespace
 * is namespace-qualified and a typo would silently find nothing.**
 * {@see SafeXml::child()} matches on `namespaceURI`, so a misspelled URI does
 * not raise — it returns null, and a null from a lookup reads as "the element
 * was absent", which is how a validator comes to skip a check it believes it
 * performed.
 *
 * The prefixes (`samlp:`, `saml:`) are conventional and carry no meaning: XML
 * namespaces are the URIs. Nothing here should ever compare a prefix.
 */
final readonly class SamlNamespaces
{
    /** `<samlp:Response>`, `<samlp:Status>`, `<samlp:Extensions>`. */
    public const string PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

    /** `<saml:Assertion>` and everything inside it. */
    public const string ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /** XML-DSig, for `<ds:Signature>`. */
    public const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /** XML Encryption, for the `<EncryptedAssertion>` DocUp refuses. */
    public const string XMLENC = 'http://www.w3.org/2001/04/xmlenc#';
}
