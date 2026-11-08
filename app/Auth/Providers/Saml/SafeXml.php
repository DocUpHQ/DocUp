<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Saml;

use DOMDocument;

/**
 * 🛑 The one place SAML XML becomes a document, and the only one.
 *
 * §8.12.18 requires "XML entity expansion disabled". §17's Phase 25 exit
 * criteria go further and ask for something stronger than a disabled feature:
 *
 * > "…and the XXE payload **provably never reaches an entity-expanding
 * > parser**."
 *
 * ## 🛑 Why a flag is not a proof
 *
 * The usual answer is `LIBXML_NOENT` and `libxml_disable_entity_loader()`. Both
 * are the wrong shape for what §17 asks:
 *
 * - `libxml_disable_entity_loader()` is **deprecated since PHP 8.0** and
 *   removed; code calling it is code that stopped doing anything.
 * - `LIBXML_NOENT` controls *substitution*, not parsing. The parser still reads
 *   the DTD, still builds the entity table, and `LIBXML_NOENT`'s absence is the
 *   safe setting — which is the opposite of what the name suggests and is how
 *   this gets written backwards.
 * - A billion-laughs payload needs no external entity at all. It is internal
 *   entities referring to each other, so "external entity loading is off by
 *   default in libxml 2.9+" is true and irrelevant.
 *
 * All three are statements about *how the parser behaves*. §17 asks for a
 * statement about *what the parser receives*.
 *
 * ## 🛑 So the check is on the bytes, before a parser exists
 *
 * {@see self::parse()} refuses any document containing a document type
 * declaration **before constructing a `DOMDocument` at all**. A SAML response
 * has no legitimate use for a DTD — the schema is fixed, published and
 * referenced by namespace — so there is nothing to lose and the proof is by
 * construction: on the XXE path, no parser is reached.
 *
 * That is testable in a way a flag is not: `SafeXmlTest` asserts the refusal
 * happens with the parser uninstantiated, and the corpus case records it.
 *
 * ## And then the flags too
 *
 * Belt and braces, because the byte check is a scanner and a scanner can be
 * fooled by an encoding nobody thought of. `LIBXML_NONET` so no network
 * retrieval is even attempted, and the entity-substitution flag is deliberately
 * **not** passed.
 */
final readonly class SafeXml
{
    /**
     * 🛑 The largest response DocUp will look at, in bytes.
     *
     * A SAML response with a certificate chain and a few attributes is a few
     * kilobytes. 512 KiB is generous and still a bound — and it is checked
     * before the byte scan, so a megabyte of nested entities costs one
     * `strlen` rather than a scan.
     */
    public const int MAX_BYTES = 512 * 1024;

    /**
     * 🛑 The largest number of elements DocUp will accept in one document.
     *
     * The second half of the expansion defence. A document with no DTD can
     * still be enormous by being deeply nested or very wide, and a parser that
     * accepted it would spend memory before any signature was checked.
     */
    public const int MAX_ELEMENTS = 10_000;

    /**
     * Parse a SAML document, or refuse it.
     *
     * 🛑 The order is the requirement. Size, then the DOCTYPE scan, then — and
     * only then — a parser. Anything that reorders these loses §17's proof.
     *
     * @throws SamlRefused
     */
    public static function parse(string $xml): \DOMDocument
    {
        if ($xml === '') {
            throw SamlRefused::of(SamlRejection::ResponseMalformed, 'the response is empty');
        }

        if (strlen($xml) > self::MAX_BYTES) {
            throw SamlRefused::of(
                SamlRejection::ResponseTooLarge,
                'the response exceeds '.self::MAX_BYTES.' bytes',
            );
        }

        self::assertNoDoctype($xml);

        /*
         * 🛑 `libxml_use_internal_errors` so a malformed document is a return
         * value rather than a warning in a log, and the previous setting is
         * restored — this runs inside a request that may be doing other XML.
         */
        $previous = libxml_use_internal_errors(true);
        libxml_clear_errors();

        $document = new \DOMDocument;

        /*
         * 🛑 `LIBXML_NONET` so no retrieval is attempted even if something
         * reached here with an external reference. `LIBXML_NOENT` is **not**
         * passed: its absence is what leaves entities unsubstituted, which is
         * the safe setting and reads as the opposite.
         *
         * `LIBXML_COMPACT` and the rest are absent because this is not a
         * performance path; a SAML login happens once per reader per session.
         */
        $loaded = $document->loadXML($xml, LIBXML_NONET);

        $errors = libxml_get_errors();

        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        if ($loaded === false || $document->documentElement === null) {
            throw SamlRefused::of(
                SamlRejection::ResponseMalformed,
                'the response is not well-formed XML'
                .($errors === [] ? '' : ': '.trim($errors[0]->message)),
            );
        }

        /*
         * 🛑 Checked again after parsing, because the scan above reads bytes and
         * this reads the parse. A document whose DOCTYPE the scanner missed —
         * an encoding, a byte-order mark, something not yet imagined — is still
         * refused here, before any caller sees the document.
         */
        if ($document->doctype !== null) {
            throw SamlRefused::of(
                SamlRejection::EntityDeclarationRefused,
                'the parsed document carries a document type declaration',
            );
        }

        self::assertBounded($document);

        return $document;
    }

    /**
     * 🛑 Refuse a document type declaration on the **bytes**.
     *
     * This is the function §17's "provably never reaches an entity-expanding
     * parser" rests on: it runs before `new DOMDocument`, so on this path there
     * is no parser to reach.
     *
     * The scan is deliberately crude and deliberately over-broad. It looks for
     * `<!DOCTYPE` and `<!ENTITY` case-insensitively anywhere in the document,
     * which will also refuse those strings inside a legitimate text node — and
     * that is an acceptable cost, because no SAML response has any business
     * containing either. A precise scanner would need to know where text nodes
     * are, which needs a parser, which is the thing being avoided.
     *
     * @throws SamlRefused
     */
    private static function assertNoDoctype(string $xml): void
    {
        /*
         * 🛑 Normalised for the scan only, never for the parse. An attacker
         * writing `<!doctype` or `<!DocType` is the first thing to try, and a
         * case-sensitive scan is a scan with a trivial bypass.
         *
         * Whitespace between `<!` and `DOCTYPE` is not legal XML, so there is
         * nothing to normalise there — but the scan looks for the keyword
         * rather than the full construct, so it does not matter either way.
         */
        $haystack = strtolower($xml);

        foreach (['<!doctype', '<!entity', '<!notation', '<!element', '<!attlist'] as $needle) {
            if (str_contains($haystack, $needle)) {
                throw SamlRefused::of(
                    SamlRejection::EntityDeclarationRefused,
                    'the response contains `'.$needle.'`, which DocUp refuses before parsing',
                );
            }
        }

        /*
         * 🛑 And an entity *reference*, which is the payload a DTD would be
         * carrying. The five XML predefined entities are permitted because they
         * are the standard escapes and expand to one character each; anything
         * else is a reference to a declaration DocUp has already refused, so a
         * document containing one is malformed by construction.
         */
        if (preg_match('/&(?!amp;|lt;|gt;|quot;|apos;|#[0-9]{1,7};|#x[0-9A-Fa-f]{1,6};)[A-Za-z_][^;]{0,64};/', $xml) === 1) {
            throw SamlRefused::of(
                SamlRejection::EntityDeclarationRefused,
                'the response references an entity that is not one of XML\'s five predefined ones',
            );
        }
    }

    /**
     * 🛑 The expansion bound that survives a document with no DTD.
     *
     * A billion-laughs payload needs entities, and those are refused above. This
     * is the other direction: a document that is simply vast. Counted after the
     * parse because counting before it would mean writing a second parser.
     *
     * @throws SamlRefused
     */
    private static function assertBounded(\DOMDocument $document): void
    {
        $elements = $document->getElementsByTagName('*');

        if ($elements->length > self::MAX_ELEMENTS) {
            throw SamlRefused::of(
                SamlRejection::ResponseTooLarge,
                'the response holds more than '.self::MAX_ELEMENTS.' elements',
            );
        }
    }

    /**
     * 🛑 An element's text, refusing any value that contains a comment.
     *
     * CVE-2017-11427 and its family. `textContent` concatenates descendant text
     * nodes and ignores comments, so `admin<!--x-->@evil.test` reads as
     * `admin@evil.test`. XML canonicalisation — which the signature was
     * computed over — **removes** the comment and joins the text, producing the
     * same string. So the signature covers one value and a naive reader sees
     * another, and both are "correct" according to their own rules.
     *
     * Several products were vulnerable simultaneously because everybody read
     * the value the convenient way.
     *
     * 🛑 Refused rather than normalised, and that is the safer direction: a
     * value containing a comment is not a value anybody meant to send, and
     * "normalise it the way the canonicaliser would" is a second implementation
     * of canonicalisation written by somebody who is not thinking about
     * canonicalisation.
     *
     * @throws SamlRefused
     */
    public static function text(\DOMElement $element): string
    {
        foreach ($element->childNodes as $child) {
            if ($child->nodeType === XML_COMMENT_NODE) {
                throw SamlRefused::of(
                    SamlRejection::CommentInValueRefused,
                    'a value DocUp reads contains an XML comment (CVE-2017-11427\'s family)',
                );
            }
        }

        return trim($element->textContent);
    }

    /**
     * 🛑 One child element by namespace and name, or null — and **never** a
     * descendant.
     *
     * `getElementsByTagNameNS` searches the whole subtree, which is how a
     * wrapped signature gets read: an attacker's `<Assertion>` nested anywhere
     * inside the document is found by a descendant search and looks like the
     * real one. Every lookup in this namespace walks **direct children** so the
     * structure DocUp validates is the structure DocUp read.
     */
    public static function child(\DOMNode $parent, string $namespace, string $name): ?\DOMElement
    {
        foreach ($parent->childNodes as $child) {
            if ($child instanceof \DOMElement
                && $child->localName === $name
                && $child->namespaceURI === $namespace) {
                return $child;
            }
        }

        return null;
    }

    /**
     * Every direct child with this namespace and name.
     *
     * 🛑 A list rather than the first, because §8.12.18's "exactly one
     * Assertion" is a count — and a function that returned the first would make
     * the count unobservable.
     *
     * @return list<\DOMElement>
     */
    public static function children(\DOMNode $parent, string $namespace, string $name): array
    {
        $found = [];

        foreach ($parent->childNodes as $child) {
            if ($child instanceof \DOMElement
                && $child->localName === $name
                && $child->namespaceURI === $namespace) {
                $found[] = $child;
            }
        }

        return $found;
    }
}
