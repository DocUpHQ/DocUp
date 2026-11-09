<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Branding;

use App\Branding\StylesheetStore;
use App\Serving\CachePolicy;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

/**
 * 🛑 §8.14.4's immutable, content-addressed per-theme stylesheet.
 *
 * The self-hosted font beside it is {@see ThemeFontController}, which says why
 * it is a separate controller and why §8.14.10 keeps a font off the asset host.
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
 * ## 🛑 The hash is read by NAME from the route, never from a parameter position
 *
 * `routes/branding.php` scopes these to a wildcard domain, which puts
 * `{docupBrandingHost}` **before** `{hash}` in the route's parameter list. A
 * method signature of `(string $hash)` therefore received the host, built a
 * path from it and raised a 500 — which is how this comment came to exist.
 * Reading by name is order-independent, so adding a route parameter later
 * cannot silently re-point this.
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

    public function __invoke(Request $request): SymfonyResponse
    {
        $css = $this->stylesheets->get(self::hashOf($request));

        if ($css === null) {
            return self::missing();
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
     * The `hash` route parameter, or a value that matches nothing.
     *
     * The route pattern already constrains it to 64 hex characters, so the
     * fallback is unreachable through the router. It exists because the stores
     * raise on a malformed address, and a controller that could hand them one
     * would turn a routing change into a 500.
     */
    private static function hashOf(Request $request): string
    {
        $hash = $request->route('hash');

        return is_string($hash) && preg_match('/^[0-9a-f]{64}$/', $hash) === 1
            ? $hash
            : str_repeat('f', 64);
    }

    private static function missing(): SymfonyResponse
    {
        return new Response('', 404, ['Cache-Control' => 'private, no-store']);
    }
}
