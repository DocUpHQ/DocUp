<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

/**
 * Extension to HTTP content type, from a closed allowlist.
 *
 * 🛑 **An allowlist with an inert fallback, never sniffing.** Two reasons, and
 * the second is the one that matters:
 *
 * 1. Sniffing costs a read of every file in a 50,000-file tree at ingest, and a
 *    stored type at serve time has to come from somewhere anyway.
 * 2. Content sniffing is how `logo.png` gets served as `text/html`. A build
 *    output is attacker-supplied (§8.8.2), so an unrecognised extension must
 *    resolve to something a browser will not execute. The fallback here is
 *    `application/octet-stream`, and `text/html` is reachable only from an
 *    extension that is explicitly listed.
 *
 * Note the deliberate asymmetry with §8.8.1's path segment, which that section
 * also calls a "media type": there it means the build output format (`html`,
 * `pdf`, `manifest`), here it means the per-file HTTP type. They are different
 * things and the manifest field is called `content_type` so the two cannot be
 * mistaken for one another in code.
 */
final class ContentTypes
{
    /**
     * @var array<string, string>
     *
     * Kept to what a documentation build actually emits. Adding an entry is a
     * deliberate act with a security consequence — anything listed here is a
     * type DocUp will tell a browser to trust — so the list stays short rather
     * than mirroring Apache's mime.types.
     */
    private const MAP = [
        // Markup and styling
        'html' => 'text/html; charset=utf-8',
        'htm' => 'text/html; charset=utf-8',
        'xhtml' => 'application/xhtml+xml; charset=utf-8',
        'css' => 'text/css; charset=utf-8',
        'js' => 'text/javascript; charset=utf-8',
        'mjs' => 'text/javascript; charset=utf-8',
        'map' => 'application/json; charset=utf-8',

        // Data
        'json' => 'application/json; charset=utf-8',

        /*
         * §8.9.11 names `.wasm` explicitly, and it has to be exact: a
         * WebAssembly module served as anything else is refused by
         * `WebAssembly.instantiateStreaming`, so a documentation site shipping
         * an interactive playground breaks with a console error and no clue.
         */
        'wasm' => 'application/wasm',
        'xml' => 'application/xml; charset=utf-8',
        'txt' => 'text/plain; charset=utf-8',
        'csv' => 'text/csv; charset=utf-8',
        'md' => 'text/markdown; charset=utf-8',
        'yaml' => 'text/plain; charset=utf-8',
        'yml' => 'text/plain; charset=utf-8',
        'inv' => 'application/octet-stream',

        // Images. SVG is the exception that proves the rule below.
        'png' => 'image/png',
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'gif' => 'image/gif',
        'webp' => 'image/webp',
        'avif' => 'image/avif',
        'ico' => 'image/vnd.microsoft.icon',
        'bmp' => 'image/bmp',
        'svg' => 'image/svg+xml',

        // Fonts
        'woff' => 'font/woff',
        'woff2' => 'font/woff2',
        'ttf' => 'font/ttf',
        'otf' => 'font/otf',
        'eot' => 'application/vnd.ms-fontobject',

        // Documents and archives a build legitimately ships
        'pdf' => 'application/pdf',
        'epub' => 'application/epub+zip',
        'zip' => 'application/zip',
        'gz' => 'application/gzip',

        // Media
        'mp4' => 'video/mp4',
        'webm' => 'video/webm',
        'mp3' => 'audio/mpeg',
        'ogg' => 'audio/ogg',
        'wav' => 'audio/wav',
    ];

    /** What an unrecognised extension resolves to: inert, by design. */
    public const FALLBACK = 'application/octet-stream';

    /**
     * The content type for a manifest path.
     *
     * 🛑 `svg` is in the map and that is a real risk: an SVG is a document and
     * can carry script, so serving one inline from the documentation origin
     * means executing attacker-supplied script there. It is listed because
     * documentation genuinely cannot do without diagrams, and the containment
     * is elsewhere and layered — §8.1.4 puts documentation on its own
     * registrable domain, and §8.9's response headers carry the CSP and
     * `X-Content-Type-Options: nosniff`. The note is here so that whoever
     * later wonders why SVG is allowed finds the reason rather than the gap.
     */
    public static function forPath(string $path): string
    {
        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));

        return self::MAP[$extension] ?? self::FALLBACK;
    }

    /** Whether an extension is one DocUp will name a type for. */
    public static function knows(string $extension): bool
    {
        return isset(self::MAP[strtolower($extension)]);
    }

    /**
     * Whether a path's type is known, which decides §8.9.11's disposition.
     *
     * 🛑 §8.9.11: "`Content-Disposition: attachment` for anything unknown." An
     * unknown type served inline is the sniffing risk this allowlist exists to
     * remove — `nosniff` stops a browser guessing, and `attachment` stops it
     * rendering what it was told is opaque bytes. The two work together: either
     * alone leaves a case open.
     */
    public static function isKnownPath(string $path): bool
    {
        return self::knows(pathinfo($path, PATHINFO_EXTENSION));
    }
}
