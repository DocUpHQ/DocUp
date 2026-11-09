<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Assets;

/**
 * What an uploaded branding asset is for, and therefore which pipeline it goes
 * through (§8.14.11).
 *
 * 🛑 A closed list, unlike the plugin-extendable token *types*. Each kind is a
 * distinct processing path — GD re-encoding for the three raster kinds, DOM
 * sanitisation for an SVG logo, a signature check for a WOFF2 — and a kind
 * nothing could process would be an upload that stored unvalidated bytes.
 */
enum AssetKind: string
{
    /** A wordmark or symbol. The one kind that may be an SVG. */
    case Logo = 'logo';

    /**
     * The favicon.
     *
     * 🛑 **Always re-encoded to PNG**, never passed through as `.ico`. An ICO
     * is a container format with a directory of images, which is a parser
     * DocUp would have to defend and browsers have accepted PNG favicons for
     * well over a decade.
     */
    case Favicon = 'favicon';

    /** The Open Graph and social card image (§8.14.7). */
    case SocialCard = 'social_card';

    /**
     * 🛑 §8.14.2's "self-hosted WOFF2 asset reference".
     *
     * WOFF2 only. A font is parsed by the operating system's font engine,
     * historically the richest source of remote code execution in a browser,
     * and WOFF2 is the one format every target browser reads — so accepting
     * TTF, OTF or WOFF1 would widen the attack surface for no capability.
     */
    case Font = 'font';

    /** Whether this kind is a raster image GD re-encodes. */
    public function isRaster(): bool
    {
        return $this !== self::Font;
    }

    /**
     * Whether an SVG may be uploaded for this kind.
     *
     * 🛑 Only a logo. A favicon is referenced by a `<link rel=icon>` that some
     * browsers fetch outside the page's CSP, and a social card is fetched and
     * re-served by a third-party crawler whose sanitisation DocUp knows
     * nothing about — so neither is a place to put a vector DocUp sanitised
     * under its own assumptions.
     */
    public function acceptsSvg(): bool
    {
        return $this === self::Logo;
    }

    /** The media type DocUp emits for this kind. */
    public function outputMediaType(bool $vector = false): string
    {
        if ($this === self::Font) {
            return 'font/woff2';
        }

        return $vector ? 'image/svg+xml' : 'image/png';
    }

    /** The extension the content-addressed URL carries. */
    public function extension(bool $vector = false): string
    {
        if ($this === self::Font) {
            return 'woff2';
        }

        return $vector ? 'svg' : 'png';
    }
}
