<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Branding\ThemeAssets;
use App\Http\Controllers\Branding\BrandingAssetController;
use App\Http\Controllers\Branding\ThemeFontController;
use App\Http\Controllers\Branding\ThemeStylesheetController;
use App\Support\Origins;
use Illuminate\Support\Facades\Route;

/*
|------------------------------------------------------------------------------
| Branding bytes (SPEC 8.14.4, 8.14.11)
|------------------------------------------------------------------------------
| 🛑 **A wildcard domain group, for the reason routes/edge.php gives at
| length.** Laravel matches a route that declares a domain ahead of every route
| that does not, whatever the registration order — so these routes must declare
| one to be in the same bucket as routes/docs.php's groups, and must be
| required before it to win within that bucket.
|
| Without the wildcard, `/_/theme/<hash>.css` on a custom domain would be
| matched by the documentation catch-all, read as a version slug and 404 — so
| every page on every custom domain would be unstyled, while every test that
| used the dashboard host passed.
|
| 🛑 **The stylesheet and the font answer on EVERY host**, and that is
| §8.14.10's requirement rather than convenience: `font-src 'self'` and the
| nonce-based dashboard CSP of §8.14.16 both mean the bytes must come from the
| origin that served the page. A stylesheet on one shared origin would need
| `style-src` widened on every documentation host, and §8.14.10 widens only
| `img-src`, deliberately — an image can be sandboxed on a neutered origin and
| a stylesheet cannot.
|
| 🛑 **No middleware group, and so no session and no cookies.** These responses
| are publicly cacheable for a year (SPEC 8.14.4). A session cookie on one
| would make `Vary: Cookie` mandatory and the shared cache entry useless, and a
| `Set-Cookie` on a response a CDN holds for a year is a session handed to
| whoever asks next.
*/

Route::domain('{docupBrandingHost}')
    ->where(['docupBrandingHost' => '.+'])
    ->group(function (): void {
        /*
         * 🛑 The hash pattern is at the router as well as in the store, and
         * the duplication is deliberate — the same reasoning the ACME
         * challenge token's pattern carries in routes/edge.php. The pattern
         * means a traversal never reaches PHP; the store means one that did
         * could still not name a path.
         */
        Route::get('/_/theme/font/{hash}.woff2', ThemeFontController::class)
            ->where('hash', '[0-9a-f]{64}')
            ->name('branding.font');

        Route::get('/_/theme/{hash}.css', ThemeStylesheetController::class)
            ->where('hash', '[0-9a-f]{64}')
            ->name('branding.stylesheet');
    });

/*
|------------------------------------------------------------------------------
| The dedicated asset host (SPEC 8.14.11)
|------------------------------------------------------------------------------
| 🛑 "rendered **only via `<img src>`** from a dedicated asset host carrying
| `default-src 'none'; sandbox`, `nosniff` and no cookies."
|
| Scoped to the configured host **exactly**, and registered before
| routes/docs.php so it wins over the single-label documentation group — the
| default asset host is a subdomain of the documentation apex, so both patterns
| match it and only order decides.
|
| 🛑 Registered only when DOCUP_ASSET_HOST is set. An installation without it
| serves branding assets from the dashboard origin, which is a degradation
| App\Branding\ThemeAssets names and `docup:doctor` reports — rather than a
| route answering on a host nobody configured.
*/

if (ThemeAssets::hasDedicatedHost()) {
    Route::domain(Origins::normalise((string) config('docup.origins.assets')))
        ->group(function (): void {
            Route::get('/{hash}.{extension}', BrandingAssetController::class)
                ->where(['hash' => '[0-9a-f]{64}', 'extension' => '[a-z0-9]{2,5}'])
                ->name('branding.asset');
        });
}
