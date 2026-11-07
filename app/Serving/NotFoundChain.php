<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * 🛑 §8.11.5's 404 chain, and ADR 0003's measurement.
 *
 * > "The 404 chain MUST be: `{path}/index.html` (302 to slash form) →
 * > ordered redirects → the matched mount's `404.html` → the primary
 * > mount's → the default version's → the branded built-in."
 *
 * Five fallbacks, and the fourth link is the one with a trap in it:
 *
 * > "🛑 A generator-supplied `404.html` is **inherently root-anchored** — a
 * > 404 page is served from arbitrary URL depth, so it cannot use relative
 * > asset paths, and MkDocs Material's measured output puts all 8 of its
 * > root-absolute references in that one file. The ingestor MUST therefore
 * > record whether a `404.html` contains root-absolute references, and the
 * > chain MUST **skip** one so flagged whenever the project is served at a
 * > non-root `path_prefix` or under a component-mount prefix, falling
 * > through to the branded built-in rather than serving a stylesheet-less
 * > page."
 *
 * **Why a generator cannot win this.** Every other page in a build knows
 * its own depth, so a generator can emit `../../css/main.css` and be right.
 * A 404 page is served for a URL that does not exist, at a depth nobody
 * chose — so relative paths are impossible and the generator has no option
 * but `/css/main.css`. That is correct when the project is at the root of
 * its host and wrong the moment it is at `/docs/`, where `/css/main.css`
 * belongs to whatever is at the root instead.
 *
 * So the choice at a prefix is between a 404 page with no styling — which
 * looks like a broken site rather than a missing page — and DocUp's own.
 * The requirement picks DocUp's, and this class is where that happens.
 */
final readonly class NotFoundChain
{
    /**
     * Which link in the chain answered, as the resolver header reports it.
     */
    public const string HEADER_RULE = 'notfound';

    /**
     * Whether a mount may serve its build's own `404.html`.
     *
     * @param  bool|null  $rootAbsolute  what the ingestor recorded; **null is
     *                                   treated as true**, because a build
     *                                   that predates the check has no answer
     *                                   and "unknown" must not read as "safe"
     */
    public static function mayServeBuildPage(string $pathPrefix, string $mountPath, ?bool $rootAbsolute): bool
    {
        if ($rootAbsolute === false) {
            /*
             * The generator emitted no root-absolute references, so the
             * page works at any depth. Nothing to skip.
             */
            return true;
        }

        return self::atOriginRoot($pathPrefix, $mountPath);
    }

    /**
     * Whether this mount's content is served from the origin's root.
     *
     * 🛑 **Both** prefixes, because either one breaks a root-absolute
     * reference identically. §8.10.1's `path_prefix` puts a whole project
     * under `/docs/`; §8.7.16's component mount puts part of one under
     * `/reference/`. A check that looked at only the first would serve a
     * stylesheet-less page to every composed project, which is the shape
     * §8.7's whole stage is about.
     */
    public static function atOriginRoot(string $pathPrefix, string $mountPath): bool
    {
        return self::isRoot($pathPrefix) && self::isRoot($mountPath);
    }

    private static function isRoot(string $prefix): bool
    {
        $trimmed = trim($prefix, '/');

        return $trimmed === '';
    }

    /**
     * The branded built-in, as bytes.
     *
     * 🛑 Static, tiny and self-contained: no stylesheet, no script, no font
     * and no image, so it cannot itself depend on a path. §8.11.8 makes
     * 404s edge-cacheable and §9.3.5 names "404 bursts" as a rate-limited
     * class, which together mean this is the response a flood receives —
     * so it has to be the cheapest thing the application can produce that
     * still tells a human what happened.
     *
     * Inline styles rather than a stylesheet for exactly that reason: a
     * `<link>` here would turn one cheap 404 into two requests, the second
     * of which is a real file lookup.
     */
    public static function builtIn(): string
    {
        return <<<'HTML'
            <!doctype html>
            <html lang="en"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <title>Not found</title>
            <style>
            :root{color-scheme:light dark}
            body{font:16px/1.6 system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh}
            main{max-width:34rem;padding:2rem;text-align:center}
            h1{font-size:1.4rem;margin:0 0 .5rem}
            p{margin:0;opacity:.75}
            </style></head>
            <body><main>
            <h1>That page is not here</h1>
            <p>The link may be out of date, or the page may have been removed in a newer version of this documentation.</p>
            </main></body></html>
            HTML;
    }
}
