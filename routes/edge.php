<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Http\Controllers\Edge\AcmeChallengeController;
use App\Http\Controllers\Edge\TlsCertificateController;
use App\Http\Controllers\Edge\TlsPermissionController;
use App\Http\Middleware\OnlyFromLoopback;
use Illuminate\Support\Facades\Route;

/*
|------------------------------------------------------------------------------
| The edge's own endpoints (SPEC 8.10.11, 8.10.14, 8.10.18; SPEC 20.2)
|------------------------------------------------------------------------------
| 🛑 **A DOMAIN-SCOPED GROUP WITH A WILDCARD HOST, AND THAT IS NOT DECORATION.**
|
| Laravel does **not** match routes in registration order alone: a route that
| declares a domain is placed ahead of every route that does not, whatever
| order they were registered in. Measured, not assumed — register a plain
| route, then a `Route::domain()` one, then another plain route, and iterate
| the collection: the domain route comes out first.
|
| That breaks two things if these routes are left unscoped, and both are
| silent:
|
|   🛑 SPEC 8.10.18 requires `/.well-known/acme-challenge/*` to be "matched
|      before the documentation catch-all". Unscoped, it is matched AFTER —
|      routes/docs.php's custom-domain group declares a domain and therefore
|      wins on every multi-label host. The CA's validation then fails against
|      SPEC 8.9.3's hard 404, the error appears at the CA, and nothing is
|      logged here.
|
|   🛑 The proxy calls the permission endpoint at `http://127.0.0.1/...`, and
|      `127.0.0.1` is a **multi-label host** — the custom-domain pattern
|      accepts digits — so `/_/edge/tls-permission` would have been answered
|      by the documentation catch-all as an unknown host. Every on-demand
|      issuance in production would have been refused, while every test that
|      requested `localhost` (a single label, which that group excludes)
|      passed.
|
| So the group declares a domain that matches anything, which puts it in the
| same bucket as the documentation groups — and within that bucket
| registration order does hold, so being required before routes/docs.php puts
| it first. The host is captured and never read: these endpoints answer on
| whatever host the proxy happens to call with, and what guards them is the
| source address (see App\Http\Middleware\OnlyFromLoopback).
|
| 🛑 **No `web` group, and no session.** SPEC 8.10.11 requires the permission
| endpoint to be "internal, session-free, plaintext", answering "in under 5
| ms". A session would mean a cookie, a database read and a write, on a path
| the proxy calls during a TLS handshake.
*/

Route::domain('{docupEdgeHost}')
    ->where(['docupEdgeHost' => '.+'])
    ->group(function (): void {
        Route::middleware([OnlyFromLoopback::class])->group(function (): void {
            Route::get('/_/edge/tls-permission', TlsPermissionController::class)
                ->name('edge.tls.permission');

            Route::get('/_/edge/certificate', TlsCertificateController::class)
                ->name('edge.tls.certificate');
        });

        /*
         * 🛑 This one is NOT loopback-only: the certificate authority fetches
         * it from the public internet, which is the entire mechanism of an
         * `http-01` challenge. App\Http\Controllers\Edge\AcmeChallengeController
         * explains why that is safe — the value proves nothing to anyone who
         * does not already hold the account key.
         *
         * The token pattern is base64url, which is what RFC 8555 §8.3 says a
         * token is. Constrained at the router as well as validated in the
         * challenge store, for the reason the downloads route in
         * routes/docs.php gives: the pattern means a traversal never reaches
         * PHP, and the store means one that did could still not name a cache
         * key.
         */
        Route::get('/.well-known/acme-challenge/{token}', AcmeChallengeController::class)
            ->where('token', '[A-Za-z0-9_-]{1,255}')
            ->name('edge.acme.challenge');
    });
