<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Branding;

use App\Branding\StylesheetStore;
use App\Branding\ThemeAssets;
use App\Serving\CachePolicy;
use Illuminate\Http\Response;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

/**
 * 🛑 §8.14.4's immutable, content-addressed per-theme stylesheet.
 *
 * ## Why this is a controller and not a static file on the edge
 *
 * The bytes are generated — a `:root` block of custom-property declarations
 * built from the resolved cascade — so there is no artifact for the edge to
 * serve. §4.3/2's "documentation bytes never traverse PHP" is about
 * **documentation**: a theme stylesheet is DocUp's own output, it is tiny, and
 * after the first request it is served from the browser and the edge for a year
 * (§8.14.4's `immutable`). One PHP call per distinct theme per cache lifetime.
 *
 * ## 🛑 No reader dimension, so no authorisation
 *
 * The URL is a SHA-256 of the stylesheet's own bytes. There is nothing to
 * authorise: the response is identical for every caller, and a caller who has
 * not been served a page naming the hash cannot guess it.
 * {@see CachePolicy::forImmutableBrandingAsset()} is where the public
 * cacheability decision lives and where its argument is written out — §9.3.2
 * requires one place, and this is not it.
 *
 * ## A 404 is a real answer
 *
 * {@see StylesheetStore} says why: a hash identifies a resolved cascade, and
 * there is no reverse lookup from one to a theme. A miss means a page cached
 * longer than its stylesheet was kept, and it degrades to an unstyled page
 * rather than a wrongly-styled one.
 */
final readonly class ThemeStylesheetController
{
    public function __construct(private StylesheetStore $stylesheets) {}

    public function __invoke(string $hash): SymfonyResponse
    {
        $css = $this->stylesheets->get($hash);

        if ($css === null) {
            return new Response('', 404, ['Cache-Control' => 'private, no-store']);
        }

        return new Response($css, 200, [
            'Content-Type' => 'text/css; charset=utf-8',
            /*
             * 🛑 `nosniff` even on a stylesheet DocUp generated, and the reason
             * is the one §8.14.11 gives for the asset host: a response whose
             * type a browser may re-guess is a response whose behaviour is not
             * DocUp's to decide. These bytes come from the compiler and are
             * always CSS, so declaring that nothing may second-guess it costs
             * nothing and removes a class of question.
             */
            'X-Content-Type-Options' => 'nosniff',
            ...CachePolicy::forImmutableBrandingAsset()->headers(),
        ]);
    }

    /**
     * 🛑 §8.14.2's self-hosted font, under §8.14.10's `font-src 'self'`.
     *
     * On the application's own origins rather than the asset host, which is
     * §8.14.10's own split: `img-src 'self' data: <asset-host>` and
     * `font-src 'self'`. An image can be sandboxed on a neutered origin; a
     * font is handed to the operating system's font engine, so it stays on an
     * origin DocUp controls and is never reachable with a `sandbox` directive
     * that would make it a null origin.
     */
    public function font(string $hash): SymfonyResponse
    {
        $bytes = ThemeAssets::store()->get($hash, 'woff2');

        if ($bytes === null) {
            return new Response('', 404, ['Cache-Control' => 'private, no-store']);
        }

        return new Response($bytes, 200, [
            'Content-Type' => 'font/woff2',
            'X-Content-Type-Options' => 'nosniff',
            ...CachePolicy::forImmutableBrandingAsset()->headers(),
        ]);
    }
}
