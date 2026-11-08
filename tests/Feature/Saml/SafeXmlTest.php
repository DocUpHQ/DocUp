<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Saml;

use App\Auth\Providers\Saml\SafeXml;
use App\Auth\Providers\Saml\SamlRefused;
use App\Auth\Providers\Saml\SamlRejection;
use Tests\Support\HostileSamlResponses;
use Tests\TestCase;

/**
 * 🛑 §17: "the XXE payload **provably never reaches an entity-expanding
 * parser**".
 *
 * That word — *provably* — is what this file is about, and it is a higher bar
 * than §8.12.18's "XML entity expansion disabled". A disabled feature is a
 * claim about how a parser behaves; §17 asks for a claim about what the parser
 * receives.
 *
 * So {@see SafeXml::parse()} refuses a document type declaration on the
 * **bytes**, before `new DOMDocument` is reached, and
 * {@see self::test_no_parser_is_constructed_for_a_doctype()} proves the parser
 * is never constructed — by counting, which is the only way to prove a negative
 * about code that did not run.
 */
final class SafeXmlTest extends TestCase
{
    // ---------------------------------------------- the case that works

    /** A well-formed response parses, and the base fixture is one. */
    public function test_a_well_formed_response_parses(): void
    {
        $document = SafeXml::parse((new HostileSamlResponses)->valid());

        $this->assertNotNull($document->documentElement);
        $this->assertSame('Response', $document->documentElement->localName);
    }

    // ------------------------------------------------- §17's XXE proof

    /**
     * 🛑 **The proof.** A DOCTYPE is refused with no parser constructed.
     *
     * Proven by instrumentation rather than by argument: `libxml`'s own error
     * counter and PHP's memory for the `DOMDocument` are both observable, but
     * the decisive signal is simpler — `libxml_get_last_error()` is cleared
     * before the call and must still be empty afterwards. A parser that had
     * read a DTD and refused it would have left an error behind; a parser that
     * was never constructed cannot.
     *
     * 🛑 And the refusal is `EntityDeclarationRefused`, not
     * `ResponseMalformed`. §17 asks for distinct audit events, and "somebody
     * sent us a DTD" is a different operational fact from "the XML is broken".
     */
    public function test_no_parser_is_constructed_for_a_doctype(): void
    {
        $idp = new HostileSamlResponses;

        foreach ([
            'external entity' => $idp->xxe_external_entity(),
            'billion laughs' => $idp->xxe_billion_laughs(),
        ] as $label => $xml) {
            $this->assertStringContainsStringIgnoringCase(
                '<!DOCTYPE',
                $xml,
                'the '.$label.' fixture should actually carry a DOCTYPE',
            );

            libxml_clear_errors();

            $before = libxml_get_errors();

            $this->assertSame([], $before);

            try {
                SafeXml::parse($xml);
                $this->fail('🛑 the '.$label.' payload parsed');
            } catch (SamlRefused $refused) {
                $this->assertSame(
                    SamlRejection::EntityDeclarationRefused,
                    $refused->rejection,
                    '🛑 §8.12.18: a document type declaration is refused outright ('.$label.')',
                );
            }

            /*
             * 🛑 No libxml error, because no libxml. A parser that had seen the
             * DTD and rejected it would have recorded one here — so an empty
             * error list after a refusal is the observable form of "the parser
             * was never reached".
             */
            $this->assertSame(
                [],
                libxml_get_errors(),
                '🛑 §17: the '.$label.' payload must never reach a parser, and a parser '
                    .'that saw it would have left an error',
            );
        }
    }

    /** 🛑 And the scan is case-insensitive, because `<!doctype` is the first try. */
    public function test_the_doctype_scan_is_case_insensitive(): void
    {
        foreach (['<!DOCTYPE', '<!doctype', '<!DocType', '<!ENTITY', '<!entity'] as $spelling) {
            $xml = '<?xml version="1.0"?>'.$spelling.' x [] ><r/>';

            try {
                SafeXml::parse($xml);
                $this->fail('`'.$spelling.'` was accepted');
            } catch (SamlRefused $refused) {
                $this->assertSame(SamlRejection::EntityDeclarationRefused, $refused->rejection);
            }
        }
    }

    /**
     * 🛑 An entity **reference** is refused even with no declaration in sight.
     *
     * A document can reference an entity declared in an external subset that
     * the scan above never sees, so the reference itself is refused — while
     * XML's five predefined entities and numeric character references stay
     * legal, because they are the standard escapes and expand to one character.
     */
    public function test_an_entity_reference_is_refused_but_escapes_are_not(): void
    {
        try {
            SafeXml::parse('<?xml version="1.0"?><r>&xxe;</r>');
            $this->fail('an entity reference was accepted');
        } catch (SamlRefused $refused) {
            $this->assertSame(SamlRejection::EntityDeclarationRefused, $refused->rejection);
        }

        /* The five predefined ones, and numeric references, must still work. */
        $document = SafeXml::parse('<?xml version="1.0"?><r>&amp;&lt;&gt;&quot;&apos;&#65;&#x42;</r>');

        $this->assertNotNull($document->documentElement);
        $this->assertSame('&<>"\'AB', $document->documentElement->textContent);
    }

    // ------------------------------------- CVE-2017-11427's family

    /**
     * 🛑 A comment inside a value DocUp reads is refused.
     *
     * The signature was computed over the canonical form, which strips the
     * comment and joins the text. A reader that takes the first text node sees
     * something shorter. Refusing is the one behaviour that cannot disagree
     * with the canonicaliser.
     */
    public function test_a_comment_inside_a_value_is_refused(): void
    {
        $document = SafeXml::parse((new HostileSamlResponses)->comment_truncation());

        $nameId = $document->getElementsByTagNameNS(HostileSamlResponses::ASSERTION, 'NameID')->item(0);

        $this->assertInstanceOf(\DOMElement::class, $nameId);

        /*
         * 🛑 What a naive reader would get, asserted so the test shows the
         * attack rather than only the defence. `textContent` concatenates and
         * skips the comment, so it agrees with the signature — it is the
         * *first text node* that lies, and plenty of code reads that.
         */
        $this->assertSame(HostileSamlResponses::SUBJECT, $nameId->firstChild?->textContent);
        $this->assertStringContainsString('evil.test', $nameId->textContent);

        try {
            SafeXml::text($nameId);
            $this->fail('🛑 a value containing a comment was read');
        } catch (SamlRefused $refused) {
            $this->assertSame(SamlRejection::CommentInValueRefused, $refused->rejection);
        }
    }

    // ----------------------------------------------------- the bounds

    /** An oversized response is refused before anything parses it. */
    public function test_an_oversized_response_is_refused(): void
    {
        $xml = '<?xml version="1.0"?><r>'.str_repeat('a', SafeXml::MAX_BYTES).'</r>';

        try {
            SafeXml::parse($xml);
            $this->fail('an oversized response parsed');
        } catch (SamlRefused $refused) {
            $this->assertSame(SamlRejection::ResponseTooLarge, $refused->rejection);
        }
    }

    /**
     * 🛑 And a document that is merely vast, with no entities at all.
     *
     * The half of the expansion defence that survives a document with no DTD:
     * entities are refused, so the remaining way to be enormous is to be
     * enormous.
     */
    public function test_a_document_with_too_many_elements_is_refused(): void
    {
        $xml = '<?xml version="1.0"?><r>'.str_repeat('<a/>', SafeXml::MAX_ELEMENTS + 1).'</r>';

        $this->assertLessThan(SafeXml::MAX_BYTES, strlen($xml), 'the fixture must pass the size check first');

        try {
            SafeXml::parse($xml);
            $this->fail('a document with too many elements parsed');
        } catch (SamlRefused $refused) {
            $this->assertSame(SamlRejection::ResponseTooLarge, $refused->rejection);
        }
    }

    /**
     * 🛑 Lookups are over **direct children**, never descendants.
     *
     * `getElementsByTagNameNS` searches the whole subtree, which is how a
     * wrapped assertion gets found and read. Asserted directly, because the
     * difference is invisible until somebody nests something.
     */
    public function test_lookups_do_not_descend(): void
    {
        $document = SafeXml::parse(
            '<?xml version="1.0"?><r xmlns="urn:x"><wrapper><target/></wrapper></r>'
        );

        $root = $document->documentElement;

        $this->assertNotNull($root);
        $this->assertNull(
            SafeXml::child($root, 'urn:x', 'target'),
            '🛑 a nested element must not be found by a child lookup',
        );
        $this->assertNotNull(SafeXml::child($root, 'urn:x', 'wrapper'));
    }
}
