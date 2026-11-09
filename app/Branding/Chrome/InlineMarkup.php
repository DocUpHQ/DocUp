<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Chrome;

use App\Branding\Assets\SvgSanitiser;
use App\Branding\TokenRefused;
use App\Branding\TokenRejection;
use Dom\Element;
use Dom\HTMLDocument;
use Dom\Node;

/**
 * 🛑 §8.14.3's "announcement with a **tiny** inline-tag allowlist".
 *
 * Five elements and one attribute. That is the whole of what a tenant may put
 * in an announcement banner, and the smallness is the requirement rather than a
 * starting point — §19/37 records why no template engine is exposed at all,
 * and an allowlist that grew a `<div>` would be the first step back toward one.
 *
 * ## 🛑 Re-serialised from a new document, like the SVG sanitiser
 *
 * Parsed with `Dom\HTMLDocument`, which is a real HTML5 parser, and then
 * **copied** node by node into output text that this class writes. Nothing the
 * parser produced is echoed. The reason is the one {@see SvgSanitiser}
 * gives at length: a removal pass over a mutating tree skips siblings, and a
 * copy pass cannot.
 *
 * It is also why an HTML5 parser is the right tool rather than a regular
 * expression. `<strong onmouseover=x>` and `<strong/onmouseover=x>` and
 * `<strong\nonmouseover=x>` are one thing to a parser and three to a pattern,
 * and the parser is the thing whose agreement with the browser matters.
 *
 * ## What `<a>` may point at
 *
 * {@see SafeHref} decides, and it is the same rule the navigation and footer
 * links use. A `javascript:` announcement link would be §8.14.8's "tenant
 * JavaScript … in portal or documentation chrome" wearing a different hat.
 */
final class InlineMarkup
{
    /**
     * The five.
     *
     * `strong` and `em` for emphasis, `code` because an announcement is often
     * about a version or a flag, `a` because an announcement that cannot link
     * to the thing it announces is half an announcement, and `br` because a
     * two-line banner is a reasonable thing to want.
     *
     * 🛑 `b` and `i` are absent: they are presentational aliases, and offering
     * two spellings of one thing doubles what has to be reviewed for nothing.
     *
     * @var list<string>
     */
    private const ELEMENTS = ['strong', 'em', 'code', 'a', 'br'];

    /** How deep nesting may go. Five inline elements do not need more. */
    private const MAX_DEPTH = 4;

    /**
     * Sanitise one announcement fragment.
     *
     * @param  string  $path  for the rejection
     *
     * @throws TokenRefused
     */
    public static function sanitise(string $html, string $path, int $maxCharacters): Announcement
    {
        if (! mb_check_encoding($html, 'UTF-8')) {
            throw TokenRefused::of(TokenRejection::MarkupRefused, $path, 'not valid UTF-8');
        }

        if (mb_strlen($html) > $maxCharacters) {
            throw TokenRefused::of(
                TokenRejection::MarkupRefused,
                $path,
                sprintf('%d characters; the limit is %d', mb_strlen($html), $maxCharacters),
            );
        }

        if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/u', $html) === 1) {
            throw TokenRefused::of(TokenRejection::MarkupRefused, $path, 'a control character');
        }

        /*
         * 🛑 Parsed as a fragment inside a container element, so the parser's
         * own tree repair does not invent a `<body>` the copy pass would then
         * have to recognise. `createFromString` on a bare fragment is well
         * defined for this shape and the wrapper is dropped by the copy.
         */
        $document = HTMLDocument::createFromString(
            '<!DOCTYPE html><body><div id="docup-announcement">'.$html.'</div>',
            LIBXML_NOERROR,
        );

        $container = $document->getElementById('docup-announcement');

        if (! $container instanceof Element) {
            throw TokenRefused::of(TokenRejection::MarkupRefused, $path, 'the fragment would not parse');
        }

        $removed = [];
        $output = self::copyChildren($container, $removed, 0, $path);

        if (trim(strip_tags($output)) === '') {
            throw TokenRefused::of(TokenRejection::MarkupRefused, $path, 'no text survived sanitisation');
        }

        return new Announcement($output, array_values(array_unique($removed)));
    }

    /**
     * Copy the permitted children of one node to text.
     *
     * @param  list<string>  $removed
     *
     * @throws TokenRefused
     */
    private static function copyChildren(Node $parent, array &$removed, int $depth, string $path): string
    {
        if ($depth > self::MAX_DEPTH) {
            $removed[] = 'nesting deeper than '.self::MAX_DEPTH.' levels';

            return '';
        }

        $output = '';

        foreach ($parent->childNodes as $child) {
            if ($child->nodeType === XML_TEXT_NODE) {
                /*
                 * 🛑 Escaped by DocUp on the way out, from the parser's decoded
                 * text. So `&lt;script&gt;` in the input is text in the tree and
                 * `&lt;script&gt;` in the output — it round-trips as text and
                 * cannot become markup, whatever the input's encoding depth.
                 */
                $output .= htmlspecialchars($child->textContent, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

                continue;
            }

            if (! $child instanceof Element) {
                /* A comment, or a processing instruction. Neither is text. */
                continue;
            }

            $name = strtolower($child->localName);

            if (! in_array($name, self::ELEMENTS, true)) {
                /*
                 * 🛑 The element goes and its **text stays**. An announcement
                 * wrapped in a stray `<p>` by a rich-text editor should not
                 * lose its sentence; an announcement wrapped in `<script>`
                 * should not keep its code — which is why `script` and `style`
                 * are the two cases where the subtree goes with the element.
                 */
                $removed[] = '<'.$name.'>';

                if ($name !== 'script' && $name !== 'style' && $name !== 'template') {
                    $output .= self::copyChildren($child, $removed, $depth + 1, $path);
                }

                continue;
            }

            if ($name === 'br') {
                $output .= '<br>';

                continue;
            }

            $attributes = '';

            if ($name === 'a') {
                $href = $child->getAttribute('href');

                if ($href === null || $href === '') {
                    $removed[] = 'an <a> with no href';
                } else {
                    $safe = SafeHref::parse($href, $path);
                    $attributes = sprintf(
                        ' href="%s" rel="noopener nofollow"',
                        htmlspecialchars($safe, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
                    );
                }

                foreach ($child->attributes as $attribute) {
                    if (strtolower($attribute->name) !== 'href') {
                        $removed[] = $attribute->name.' on <a>';
                    }
                }
            } else {
                foreach ($child->attributes as $attribute) {
                    $removed[] = $attribute->name.' on <'.$name.'>';
                }
            }

            $output .= '<'.$name.$attributes.'>'
                .self::copyChildren($child, $removed, $depth + 1, $path)
                .'</'.$name.'>';
        }

        return $output;
    }
}
