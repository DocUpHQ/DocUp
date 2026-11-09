<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Assets;

use App\Branding\TokenRefused;
use App\Branding\TokenRejection;
use DOMDocument;

/**
 * 🛑 §8.14.11's SVG half: "SVG MUST be DOM-sanitised against an element and
 * attribute allowlist, re-serialised, and rendered **only via `<img src>`**
 * from a dedicated asset host carrying `default-src 'none'; sandbox`,
 * `nosniff` and no cookies."
 *
 * §17's second exit criterion is this class: "An uploaded SVG containing script
 * is **sanitised** and renders via `<img>` from the asset host." Sanitised, not
 * refused — the upload succeeds and the logo still draws. A refusal would be
 * easier to implement and would mean every tenant whose design tool emitted a
 * stray `<metadata>` block got an error they could not act on.
 *
 * ## 🛑 Copied into a new document, never edited in place
 *
 * The sanitiser builds a **fresh** {@see DOMDocument} and copies the nodes the
 * allowlist admits. It does not walk the parsed tree removing things, and the
 * difference is the whole defence: a removal pass is a loop over a mutating
 * collection, where the classic bug is that removing a node shifts the index
 * and the next sibling is skipped. A copy pass cannot skip anything, because
 * nothing arrives in the output that was not deliberately written there.
 *
 * ## 🛑 Four refusals, and everything else is dropped
 *
 * The document is **refused** only when it is not an SVG DocUp can reason
 * about at all: not well-formed XML, carrying a DOCTYPE, carrying an entity
 * declaration, or rooted at something other than `<svg>`. Everything else —
 * script, event handlers, `<foreignObject>`, SMIL animation, external
 * references, `<style>` — is simply not copied.
 *
 * DOCTYPE and entities are refused rather than dropped because they are the
 * XXE and billion-laughs vectors and they act on the **parser**, before any
 * allowlist runs. A document that needs an entity substituted to make sense is
 * a document DocUp declines to understand.
 *
 * ## 🛑 `url()` is permitted here, and only as a local fragment
 *
 * §8.14.2 bans `url()` in a token value. An SVG is not a token value, and
 * `fill="url(#gradient)"` is how every gradient in every SVG works — so
 * banning it would refuse most real logos. What is banned is a `url()` that
 * leaves the document: anything but `url(#name)` is dropped, so there is no
 * spelling by which an uploaded logo fetches from a host.
 */
final class SvgSanitiser
{
    /**
     * The elements copied into the output.
     *
     * 🛑 Absent, each for its own reason: `script` and `style` (code and a CSS
     * parser DocUp would have to defend — see §18.22); `foreignObject` (an
     * escape hatch into HTML); `image` and `a` (external references, and
     * neither does anything inside an `<img>`); `use` (its `href` can name
     * another document, and a logo that needs symbol reuse can inline it);
     * every SMIL animation element (`animate`, `set`, `animateTransform` —
     * `attributeName` lets animation write an attribute the allowlist refused);
     * `filter` and its primitives (a large, rarely-exercised surface in every
     * renderer, for an effect a logo can bake in); `metadata` and `switch`.
     *
     * @var list<string>
     */
    private const ELEMENTS = [
        'svg', 'g', 'defs', 'title', 'desc', 'symbol',
        'path', 'rect', 'circle', 'ellipse', 'line', 'polyline', 'polygon',
        'linearGradient', 'radialGradient', 'stop',
        'clipPath', 'mask',
        'text', 'tspan',
    ];

    /**
     * Attributes permitted on any allowlisted element.
     *
     * Presentation and geometry only. 🛑 `style` is absent: a presentation
     * attribute says one thing and a `style` attribute is a CSS declaration
     * list, which needs the parser §18.22 has not verified. Every effect a
     * logo needs is expressible as a presentation attribute.
     *
     * @var list<string>
     */
    private const GLOBAL_ATTRIBUTES = [
        'id', 'class', 'transform',
        'fill', 'fill-opacity', 'fill-rule',
        'stroke', 'stroke-width', 'stroke-linecap', 'stroke-linejoin',
        'stroke-dasharray', 'stroke-dashoffset', 'stroke-opacity', 'stroke-miterlimit',
        'opacity', 'color', 'display', 'visibility',
        'clip-path', 'clip-rule', 'mask',
        'vector-effect', 'paint-order', 'shape-rendering', 'fill-rule',
    ];

    /**
     * Attributes permitted on one element only.
     *
     * @var array<string, list<string>>
     */
    private const ELEMENT_ATTRIBUTES = [
        'svg' => ['viewBox', 'width', 'height', 'preserveAspectRatio', 'xmlns', 'version'],
        'symbol' => ['viewBox', 'preserveAspectRatio'],
        'path' => ['d', 'pathLength'],
        'rect' => ['x', 'y', 'width', 'height', 'rx', 'ry'],
        'circle' => ['cx', 'cy', 'r'],
        'ellipse' => ['cx', 'cy', 'rx', 'ry'],
        'line' => ['x1', 'y1', 'x2', 'y2'],
        'polyline' => ['points'],
        'polygon' => ['points'],
        'linearGradient' => ['x1', 'y1', 'x2', 'y2', 'gradientUnits', 'gradientTransform', 'spreadMethod', 'href'],
        'radialGradient' => ['cx', 'cy', 'r', 'fx', 'fy', 'fr', 'gradientUnits', 'gradientTransform', 'spreadMethod'],
        'stop' => ['offset', 'stop-color', 'stop-opacity'],
        'clipPath' => ['clipPathUnits'],
        'mask' => ['maskUnits', 'maskContentUnits', 'x', 'y', 'width', 'height'],
        'text' => ['x', 'y', 'dx', 'dy', 'text-anchor', 'font-family', 'font-size', 'font-weight', 'font-style', 'letter-spacing'],
        'tspan' => ['x', 'y', 'dx', 'dy', 'text-anchor', 'font-family', 'font-size', 'font-weight', 'font-style', 'letter-spacing'],
    ];

    /**
     * Attributes whose value may be a paint reference, and so may carry a
     * local `url(#name)`.
     *
     * @var list<string>
     */
    private const PAINT_ATTRIBUTES = ['fill', 'stroke', 'clip-path', 'mask', 'stop-color', 'color'];

    /** The SVG namespace. An element outside it is not copied. */
    private const SVG_NAMESPACE = 'http://www.w3.org/2000/svg';

    /** How deep the copy will recurse. A pathological nesting is a parser bomb. */
    private const MAX_DEPTH = 32;

    /**
     * Sanitise one SVG document.
     *
     * @param  string  $svg  the uploaded bytes
     *
     * @throws TokenRefused when the document is not an SVG DocUp will reason about
     */
    public static function sanitise(string $svg): SanitisedSvg
    {
        if (! mb_check_encoding($svg, 'UTF-8')) {
            throw TokenRefused::of(TokenRejection::SvgNotWellFormed, 'svg', 'not valid UTF-8');
        }

        /*
         * 🛑 Checked on the raw bytes, before the parser sees them. libxml can
         * be told not to substitute entities, and a document whose meaning
         * depends on a declaration DocUp refuses to expand is a document whose
         * sanitised form would differ from what the author intended — so it is
         * better refused than silently reinterpreted. This is also the
         * billion-laughs defence, and it is upstream of any limit.
         */
        if (preg_match('/<!DOCTYPE/i', $svg) === 1) {
            throw TokenRefused::of(
                TokenRejection::SvgNotWellFormed,
                'svg',
                'a DOCTYPE declaration, which is the XXE and entity-expansion surface',
            );
        }

        if (preg_match('/<!ENTITY/i', $svg) === 1) {
            throw TokenRefused::of(TokenRejection::SvgNotWellFormed, 'svg', 'an entity declaration');
        }

        $source = new \DOMDocument;
        $source->preserveWhiteSpace = false;

        $previous = libxml_use_internal_errors(true);
        libxml_clear_errors();

        /*
         * 🛑 `LIBXML_NONET` so the parser cannot fetch anything even if a
         * declaration slipped past the checks above, and `LIBXML_NOERROR` so a
         * malformed document is a false return rather than a warning in the
         * operator's log.
         */
        $loaded = $source->loadXML($svg, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);

        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        if ($loaded === false || ! $source->documentElement instanceof \DOMElement) {
            throw TokenRefused::of(TokenRejection::SvgNotWellFormed, 'svg', 'not well-formed XML');
        }

        $root = $source->documentElement;

        if ($root->localName !== 'svg') {
            throw TokenRefused::of(
                TokenRejection::SvgNotWellFormed,
                'svg',
                sprintf('the root element is <%s>, not <svg>', $root->localName),
            );
        }

        $output = new \DOMDocument('1.0', 'UTF-8');
        $output->formatOutput = false;

        $removed = [];
        $copiedRoot = self::copyElement($root, $output, $removed, 0);

        if (! $copiedRoot instanceof \DOMElement) {
            throw TokenRefused::of(TokenRejection::SvgNotWellFormed, 'svg', 'the root element did not survive sanitisation');
        }

        /*
         * The namespace is set by DocUp rather than copied, so a document that
         * declared the right root in the wrong namespace still emits a
         * well-namespaced SVG — and so a copied `xmlns` cannot point somewhere
         * else.
         */
        $copiedRoot->setAttribute('xmlns', self::SVG_NAMESPACE);
        $output->appendChild($copiedRoot);

        $serialised = $output->saveXML($output->documentElement);

        if ($serialised === false) {
            throw TokenRefused::of(TokenRejection::SvgNotWellFormed, 'svg', 'the sanitised document would not serialise');
        }

        return new SanitisedSvg(
            '<?xml version="1.0" encoding="UTF-8"?>'."\n".$serialised."\n",
            array_values(array_unique($removed)),
        );
    }

    /**
     * Copy one element, and its permitted attributes and children, or nothing.
     *
     * @param  list<string>  $removed
     */
    private static function copyElement(\DOMElement $element, \DOMDocument $output, array &$removed, int $depth): ?\DOMElement
    {
        if ($depth > self::MAX_DEPTH) {
            $removed[] = 'nesting deeper than '.self::MAX_DEPTH.' levels';

            return null;
        }

        $name = $element->localName ?? '';

        /*
         * 🛑 The namespace is checked as well as the name. `<svg:script>` and
         * an `<html:script>` smuggled into an SVG document both have a local
         * name the allowlist would reject — but `<xhtml:title>` has one it
         * would accept, and copying it would put an HTML element in the output
         * under an SVG name.
         */
        if ($element->namespaceURI !== null && $element->namespaceURI !== self::SVG_NAMESPACE) {
            $removed[] = '<'.($element->nodeName).'> (outside the SVG namespace)';

            return null;
        }

        if (! in_array($name, self::ELEMENTS, true)) {
            $removed[] = '<'.$name.'>';

            return null;
        }

        $copy = $output->createElementNS(self::SVG_NAMESPACE, $name);

        foreach (self::attributesOf($element) as $attribute) {
            $permitted = self::permittedAttribute($name, $attribute, $removed);

            if ($permitted !== null) {
                $copy->setAttribute($attribute->name, $permitted);
            }
        }

        foreach (self::childrenOf($element) as $child) {
            if ($child instanceof \DOMElement) {
                $copiedChild = self::copyElement($child, $output, $removed, $depth + 1);

                if ($copiedChild instanceof \DOMElement) {
                    $copy->appendChild($copiedChild);
                }

                continue;
            }

            /*
             * Text is copied for `<title>`, `<desc>`, `<text>` and `<tspan>`;
             * `createTextNode` escapes it, so there is no spelling of a text
             * node that reopens markup. A comment or a processing instruction
             * is not copied — `<?xml-stylesheet?>` is a PI that pulls a
             * stylesheet, and a comment carries no meaning a logo needs.
             */
            if ($child->nodeType === XML_TEXT_NODE || $child->nodeType === XML_CDATA_SECTION_NODE) {
                $copy->appendChild($output->createTextNode($child->textContent));

                continue;
            }

            if ($child->nodeType === XML_PI_NODE) {
                $removed[] = 'a processing instruction';
            }
        }

        return $copy;
    }

    /**
     * The value to copy for one attribute, or null to drop it.
     *
     * @param  list<string>  $removed
     */
    private static function permittedAttribute(string $element, \DOMAttr $attribute, array &$removed): ?string
    {
        $name = $attribute->name;
        $lower = strtolower($name);

        /*
         * 🛑 Named explicitly as well as being absent from the allowlist, so
         * the removal record says "an event handler" rather than listing
         * `onload` as an unknown attribute. An operator reading the record
         * should be able to tell the difference between a design tool's stray
         * `data-name` and somebody's `onload`.
         */
        if (str_starts_with($lower, 'on')) {
            $removed[] = 'an event handler ('.$name.')';

            return null;
        }

        /*
         * 🛑 EVERY namespaced attribute, with no exception.
         *
         * `xlink:href` is the external-reference vector and `xlink:` is
         * deprecated anyway; the rest carry editor metadata (`inkscape:`,
         * `sodipodi:`) that nothing renders.
         *
         * 🛑 There WAS an exception for `xml:space`, and it was dead code —
         * measured, not assumed. A parsed `xml:space` arrives with `name` set
         * to `space` and the prefix carried separately, so the check never
         * matched and the attribute was dropped as namespaced like any other.
         * An entry in a security allowlist that does nothing is worse than no
         * entry: the next reader concludes namespaced attributes are handled
         * selectively here, and they are not. `<text>` loses `xml:space`,
         * which collapses a run of spaces in a logo's text and is the right
         * trade for not reconstructing a namespace on the output element.
         */
        if ($attribute->namespaceURI !== null) {
            $removed[] = $name.' (namespaced)';

            return null;
        }

        $allowed = in_array($name, self::GLOBAL_ATTRIBUTES, true)
            || in_array($name, self::ELEMENT_ATTRIBUTES[$element] ?? [], true);

        if (! $allowed) {
            $removed[] = $name;

            return null;
        }

        $value = $attribute->value;

        /*
         * 🛑 A `url()` that leaves the document. Permitted only as
         * `url(#name)`, which is how every gradient and clip path in every SVG
         * is referenced — see the class docblock. Anything else is dropped
         * rather than refused, because a design tool that wrote an absolute
         * reference has produced a logo that still draws without it.
         */
        if (stripos($value, 'url(') !== false) {
            if (! in_array($name, self::PAINT_ATTRIBUTES, true)) {
                $removed[] = $name.' (a url() where none is permitted)';

                return null;
            }

            if (preg_match('/^url\(\s*#[A-Za-z_][\w:.-]*\s*\)$/', trim($value)) !== 1) {
                $removed[] = $name.' (a url() that leaves the document)';

                return null;
            }
        }

        /*
         * 🛑 `href` survives on a gradient only, for `<linearGradient href="#other">`
         * — and only as a local fragment. Anywhere else it is not in the
         * allowlist at all.
         */
        if ($lower === 'href' && preg_match('/^#[A-Za-z_][\w:.-]*$/', trim($value)) !== 1) {
            $removed[] = 'href (not a local fragment)';

            return null;
        }

        /* A `data:` or `javascript:` scheme in any surviving attribute value. */
        if (preg_match('/(?:data|javascript|vbscript)\s*:/i', $value) === 1) {
            $removed[] = $name.' (a scheme in its value)';

            return null;
        }

        return $value;
    }

    /** @return list<\DOMAttr> */
    private static function attributesOf(\DOMElement $element): array
    {
        $attributes = [];

        /*
         * No `instanceof` here: a `DOMNamedNodeMap` over an element yields
         * `DOMAttr` and nothing else, so the guard could never fail — and a
         * guard that cannot fail is one a reader has to think about before
         * concluding it does nothing.
         */
        foreach ($element->attributes as $attribute) {
            $attributes[] = $attribute;
        }

        return $attributes;
    }

    /** @return list<\DOMNode> */
    private static function childrenOf(\DOMElement $element): array
    {
        $children = [];

        foreach ($element->childNodes as $child) {
            $children[] = $child;
        }

        return $children;
    }
}
