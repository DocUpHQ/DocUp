<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Http\Controllers\Serving\DocumentController;
use App\Http\Controllers\Serving\DownloadController;
use App\Http\Controllers\Serving\ProvenanceController;
use App\Http\Middleware\RejectNonCanonicalPath;
use App\Serving\OfflineFormat;
use Illuminate\Support\Facades\Route;

/*
|------------------------------------------------------------------------------
| The documentation origin (SPEC 8.9)
|------------------------------------------------------------------------------
| 🛑 A separate route file and a separate middleware group, because SPEC 8.1.4
| puts documentation on its own registrable domain: "Built documentation is
| attacker-controlled HTML and JavaScript; on a shared registrable domain it can
| toss cookies at the dashboard, Clear-Site-Data spans tenants, and Laravel's
| TrustHosts default trusts subdomains of APP_URL."
|
| So nothing from the `web` group applies here. No session, no CSRF token, no
| Inertia, no cookies at all — a reader of public documentation has no identity,
| and a cookie on this origin would be one the documentation's own JavaScript
| could read.
|
| 🛑 RejectNonCanonicalPath is FIRST and nothing may precede it. SPEC 8.9.6: the
| rejection happens "before any cache lookup or resolution", and "its position in
| the pipeline is the whole of its value".
|
| 🛑 **Scoped by domain, to the documentation and preview apexes only.** Not a
| fallback route, and not an unconstrained catch-all. A catch-all would answer on
| the dashboard host too, where SPEC 8.1.4's whole point is that the two origins
| stay apart; a fallback would let a custom domain reach the dashboard's own `/`
| route before anything checked whether it serves documentation at all.
|
| Custom domains are 🛑 **explicitly out of scope for Phase 04** (SPEC 17), which
| is why only these two shapes are registered. Phase 18 brings domain claims and
| verification, and the host matcher already offers the custom-domain candidate
| first (SPEC 8.9.3) — the route table is what has not caught up, deliberately,
| rather than the resolver.
*/

$apexes = array_values(array_filter([
    config('docup.origins.docs'),
    config('docup.origins.preview'),
], static fn (mixed $apex): bool => is_string($apex) && $apex !== ''));

foreach ($apexes as $index => $apex) {
    /*
     * One label under the apex. SPEC 8.9.3 resolves a "single-label default
     * subdomain", and the pattern enforces the same thing the matcher does:
     * `a.b.docs.example.com` matches nothing, because a wildcard certificate
     * covers one label and a nested name is a misconfiguration or a probe.
     *
     * The label is captured only so the pattern can require exactly one. It is
     * never read: SPEC 8.9.4 forbids resolving a project from anything but the
     * host and path, and the resolver takes the whole host, so a controller
     * reading a route parameter here would be a second source of truth.
     */
    Route::domain('{docupHostLabel}.'.$apex)
        ->middleware([RejectNonCanonicalPath::class])
        ->group(function () use ($index): void {
            /*
             * SPEC 8.5.24's build provenance, at SPEC 20.2's reserved path.
             *
             * 🛑 Registered BEFORE the catch-all, and that ordering is the
             * whole reason it works. SPEC 7.3 makes `/_/` reserved and
             * unmountable, so the resolver refuses it — correctly — and a
             * provenance route declared after `/{docupPath?}` would never be
             * reached. The reserved namespace exists precisely so that routes
             * like this one can be carved out of a grammar that otherwise
             * owns every path.
             */
            Route::get('/_/provenance/{build}', [ProvenanceController::class, 'show'])
                ->where('docupHostLabel', '[a-z0-9]([a-z0-9-]*[a-z0-9])?')
                ->where('build', '[0-9a-fA-F-]{36}')
                ->name('docs.provenance.'.$index);

            /*
             * §7.3's `/_/downloads/...` — §8.4.5's offline formats.
             *
             * Before the catch-all for the same reason provenance is: `/_/`
             * is reserved and unmountable, so the resolver refuses it and a
             * route declared after `/{docupPath?}` would never be reached.
             *
             * 🛑 The format segment is constrained HERE as well as matched
             * against {@see OfflineFormat} in the controller, and the
             * duplication is deliberate. The router pattern means a request
             * for `../../etc/passwd` never reaches PHP; the enum means a
             * request that does reach PHP still cannot name a storage path.
             * Either alone would be enough today and the pair survives
             * someone relaxing one of them.
             *
             * `{language}` and `{version}` carry the same character classes
             * §8.6.6 and §8.6.12 give them. A slug outside that set cannot
             * exist, so a request carrying one is answered by the router.
             */
            Route::get('/_/downloads/{language}/{version}/{format}', DownloadController::class)
                ->where('docupHostLabel', '[a-z0-9]([a-z0-9-]*[a-z0-9])?')
                ->where('language', '[a-z]{2,3}(-[a-z0-9]{2,8})?')
                ->where('version', '[a-z0-9][a-z0-9._-]{0,79}')
                ->where('format', implode('|', OfflineFormat::values()))
                ->name('docs.downloads.'.$index);

            /*
             * One route for every documentation path. SPEC 7.3's grammar is the
             * resolver's, not the router's — a router pattern per versioning
             * scheme would be a second implementation of the grammar, and
             * SPEC 17.4 freezes exactly one.
             */
            Route::get('/{docupPath?}', DocumentController::class)
                ->where('docupHostLabel', '[a-z0-9]([a-z0-9-]*[a-z0-9])?')
                ->where('docupPath', '.*')
                /*
                 * Named by position, because Laravel requires route names to
                 * be unique and both apexes register the same route. Stable
                 * across boots — the documentation apex is index 0 and the
                 * preview apex is index 1 — so a generated URL does not change
                 * between requests, which a random suffix would have made true
                 * only by accident.
                 */
                ->name('docs.document.'.$index);
        });
}
