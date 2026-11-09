<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Branding;

use App\Branding\Assets\AssetStore;
use App\Serving\CachePolicy;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

/**
 * 🛑 §8.14.2's self-hosted font, under §8.14.10's `font-src 'self'`.
 *
 * > §8.14.2: "Fonts are catalogue names or self-hosted WOFF2 asset references;
 * > **no remote font URL ever** (an injection surface and a third-country
 * > transfer)."
 *
 * > §8.14.10: "`img-src 'self' data: <asset-host>`, `font-src 'self'`,
 * > `connect-src 'self'`"
 *
 * ## 🛑 Why a font is NOT on the asset host
 *
 * §8.14.10's split is deliberate and it is the whole reason this is a second
 * controller rather than a second route on {@see BrandingAssetController}. An
 * **image** is sandboxed on the asset host under `default-src 'none'; sandbox`,
 * which puts it in an opaque origin with scripting off. A **font** is handed to
 * the operating system's font engine — historically the richest source of
 * remote code execution in a browser — so it stays on an origin DocUp controls
 * and is never reachable under a `sandbox` directive that would make it a null
 * origin. The CSP widening §8.14.10 grants is `img-src` and not `font-src`.
 *
 * ## 🛑 A separate controller, not a second method
 *
 * The Pest `laravel` architecture preset permits a controller only the
 * conventional method names, and that rule is right here for a reason beyond
 * tidiness: a `font()` method on the stylesheet controller would share its
 * constructor, so one of the two would be reading from the wrong store the day
 * somebody changed the injected type. Two single-action controllers, two
 * explicit stores.
 */
final readonly class ThemeFontController
{
    public function __construct(private AssetStore $store) {}

    public function __invoke(Request $request): SymfonyResponse
    {
        $hash = $request->route('hash');

        /*
         * The route pattern constrains this to 64 hex characters, so the guard
         * is unreachable through the router. It is here because the store
         * raises on a malformed address, and a controller that could hand it
         * one would turn a routing change into a 500 — which is how the
         * wildcard-domain parameter was found. {@see ThemeStylesheetController}
         * records that at length.
         */
        if (! is_string($hash) || preg_match('/^[0-9a-f]{64}$/', $hash) !== 1) {
            return self::missing();
        }

        $bytes = $this->store->get($hash, 'woff2');

        if ($bytes === null) {
            return self::missing();
        }

        return new Response($bytes, 200, [
            'Content-Type' => 'font/woff2',
            'X-Content-Type-Options' => 'nosniff',
            ...CachePolicy::forImmutableBrandingAsset()->headers(),
        ]);
    }

    private static function missing(): SymfonyResponse
    {
        return new Response('', 404, ['Cache-Control' => 'private, no-store']);
    }
}
