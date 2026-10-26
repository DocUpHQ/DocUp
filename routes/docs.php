<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Http\Controllers\Serving\CompositionController;
use App\Http\Controllers\Serving\CrossReferenceController;
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
             * 🛑 SPEC 8.7.16's cross-component reference namespace.
             *
             * Two routes rather than one optional parameter, because
             * `/_/x/{component}` with no path is a real request — it names
             * the component's own root — and Laravel's optional-parameter
             * form would make the trailing slash decide which of the two it
             * was.
             *
             * The component pattern is SPEC 10.2's `components.key` shape.
             * Constrained at the router as well as looked up in the
             * manifest, for the reason the downloads route gives: the
             * pattern means a traversal never reaches PHP, and the manifest
             * lookup means one that does cannot name a storage path.
             */
            Route::get('/_/x/{component}/{docupXrefPath}', CrossReferenceController::class)
                ->where('docupHostLabel', '[a-z0-9]([a-z0-9-]*[a-z0-9])?')
                ->where('component', '[a-z0-9][a-z0-9._-]{0,99}')
                /*
                 * A leading underscore is allowed because SPEC 8.7.16's own
                 * directly-served map is `_xref.json`. Traversal is still
                 * impossible: `..` never reaches here, because
                 * RejectNonCanonicalPath runs first and SPEC 8.9.6 puts it
                 * before everything.
                 */
                ->where('docupXrefPath', '[A-Za-z0-9_][A-Za-z0-9._/-]{0,511}')
                ->name('docs.xref.'.$index);

            Route::get('/_/x/{component}', CrossReferenceController::class)
                ->where('docupHostLabel', '[a-z0-9]([a-z0-9-]*[a-z0-9])?')
                ->where('component', '[a-z0-9][a-z0-9._-]{0,99}')
                ->name('docs.xref.root.'.$index);

            /*
             * SPEC 8.7.21's `/_/composition` — the auditor's answer to "what
             * was on this URL on 2026-03-04?".
             */
            Route::get('/_/composition', CompositionController::class)
                ->where('docupHostLabel', '[a-z0-9]([a-z0-9-]*[a-z0-9])?')
                ->name('docs.composition.'.$index);

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

/*
|------------------------------------------------------------------------------
| Custom domains (SPEC 8.10, Phase 18)
|------------------------------------------------------------------------------
| 🛑 The route table catching up, which Phase 04 said in as many words it had
| not: "Custom domains are explicitly out of scope for Phase 04, which is why
| only these two shapes are registered. Phase 18 brings domain claims and
| verification, and the host matcher already offers the custom-domain candidate
| first — the route table is what has not caught up, deliberately."
|
| 🛑 **Not a fallback, and not unconstrained.** A `Route::fallback()` would let
| the dashboard's own unconstrained `/` and Fortify's `/login` match FIRST on a
| custom documentation host — the exact leak bootstrap/app.php documents, where
| a reader on an attacker-controlled origin is served the dashboard's sign-in
| form. So this is a domain-scoped group like the two above, registered before
| the dashboard, whose host pattern excludes the origins SPEC 8.1.4 keeps apart.
|
| Everything else about safety is the resolver's and it already holds: an
| unknown host is SPEC 8.9.3's hard 404 with no fallback to a default project,
| and an unverified or suspended one is refused by SPEC 8.10.6 before the mount
| list is even read. This group adds reach, not trust.
*/
$reserved = array_values(array_filter(array_map(
    static function (mixed $origin): ?string {
        if (! is_string($origin) || $origin === '') {
            return null;
        }

        $host = parse_url($origin, PHP_URL_HOST);

        return is_string($host) ? $host : $origin;
    },
    [config('docup.origins.app'), config('docup.origins.assets')],
), is_string(...)));

/*
 * A negative lookahead per reserved origin, then the hostname grammar. The
 * two apex groups above are registered first and win on their own hosts, so
 * they need no exclusion here; the dashboard and the asset host are NOT
 * domain-scoped anywhere, which is precisely why they have to be excluded by
 * name rather than by ordering.
 */
$exclusions = implode('', array_map(
    static fn (string $host): string => '(?!'.preg_quote($host, '/').'$)',
    $reserved,
));

/*
 * 🛑 The `where` goes BEFORE `group`, and that is not style. `group()`
 * returns null, so a trailing `->where()` is called on nothing and silently
 * does nothing — leaving Laravel's default host pattern, `[^.]++`, which
 * matches a single label and therefore no real custom domain at all. The
 * group then appears registered, answers nothing, and the two apex groups
 * above go on working, so the mistake is invisible until somebody points a
 * real hostname at the installation.
 */
Route::domain('{docupCustomHost}')
    ->where(['docupCustomHost' => $exclusions.'[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?'])
    ->middleware([RejectNonCanonicalPath::class])
    ->group(function (): void {
        Route::get('/_/provenance/{build}', [ProvenanceController::class, 'show'])
            ->where('build', '[0-9a-fA-F-]{36}')
            ->name('docs.custom.provenance');

        Route::get('/_/downloads/{language}/{version}/{format}', DownloadController::class)
            ->where('language', '[a-z]{2,3}(-[a-z0-9]{2,8})?')
            ->where('version', '[a-z0-9][a-z0-9._-]{0,79}')
            ->where('format', implode('|', OfflineFormat::values()))
            ->name('docs.custom.downloads');

        Route::get('/_/x/{component}/{docupXrefPath}', CrossReferenceController::class)
            ->where('component', '[a-z0-9][a-z0-9._-]{0,99}')
            ->where('docupXrefPath', '[A-Za-z0-9_][A-Za-z0-9._/-]{0,511}')
            ->name('docs.custom.xref');

        Route::get('/_/x/{component}', CrossReferenceController::class)
            ->where('component', '[a-z0-9][a-z0-9._-]{0,99}')
            ->name('docs.custom.xref.root');

        Route::get('/_/composition', CompositionController::class)
            ->name('docs.custom.composition');

        Route::get('/{docupPath?}', DocumentController::class)
            ->where('docupPath', '.*')
            ->name('docs.custom.document');
    });
