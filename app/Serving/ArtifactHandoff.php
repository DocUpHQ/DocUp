<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

use Symfony\Component\HttpFoundation\Response;

/**
 * 🛑 §8.9.8 — the authorised byte handoff. Documentation bytes never traverse
 * PHP.
 *
 * §8.9.8: "Documentation bytes MUST NOT be read by application code. The
 * application authorises and then hands off by internal redirect into a
 * location that is externally unreachable, has symlink resolution disabled
 * (`disable_symlinks on` — nginx defaults to `off`), strips `Cookie` and
 * `Authorization` toward storage, ignores internal-redirect headers returned by
 * the storage upstream (nginx honours `X-Accel-*` from **any** upstream), and
 * is never a PHP-executable document root."
 *
 * The payoff is stated in the same paragraph: "This is what buys ETags,
 * `If-None-Match` and `Range` from the web server — all three verified on a
 * 200 MB artifact with PHP's `memory_limit` at 16M, which is itself the proof
 * that no artifact byte traverses PHP (ADR 0001)." A 16 MB limit serving a
 * 200 MB file is not a benchmark; it is a proof by contradiction.
 *
 * 🛑 **Header preservation is driver-specific and must be proven per driver**
 * (§8.9.8, §18.18). Measured in ADR 0001: `caddy-intercept` preserves every
 * application header natively; `nginx-accel` **replaces the entire response
 * header set**. Under nginx, a private document would otherwise be served with
 * no `private, no-store` and no `Vary: Cookie` — §9.3.2's failure arriving
 * silently behind a correct-looking 200. That is why Caddy is the default
 * (§11.3) and why the nginx driver carries a compensating control rather than
 * being equivalent.
 */
interface ArtifactHandoff
{
    /**
     * The internal prefix both drivers redirect into.
     *
     * Matched by `deploy/Caddyfile`'s `handle_response` and by the `internal`
     * location in `deploy/nginx.conf`. It must be externally unreachable: a
     * reader who could request it directly would bypass every authorisation
     * decision the application just made.
     */
    public const INTERNAL_PREFIX = '/_internal';

    /**
     * 🛑 Every header that must survive the handoff (§8.9.8, §18.18).
     *
     * This list is the compensating control for `nginx-accel`. nginx re-emits
     * only what its configuration names, so the list is hand-maintained in two
     * places — here and in `deploy/nginx.conf` — and a permanent test asserts
     * they match. §18.18's own words on why: "the failure mode here is silent
     * security degradation, not a visible error".
     *
     * Adding a security-relevant response header to the serving path means
     * adding it here, or it will be present on Caddy and absent on nginx, and
     * nothing will fail.
     *
     * @var list<string>
     */
    public const PRESERVED_HEADERS = [
        'Cache-Control',
        'CDN-Cache-Control',
        'Vary',
        'Cache-Tag',
        'Content-Security-Policy',
        'Content-Type',
        'Content-Disposition',

        /*
         * 🛑 §8.9.13's sidecar. Dropped under `nginx-accel`, a reader receives
         * gzip bytes with no `Content-Encoding` — which is not a degraded
         * response, it is a binary download where a page should be. Listed here
         * so deploy/nginx.conf must re-emit it, and the parity test enforces
         * that it does.
         */
        'Content-Encoding',
        'Link',
        'X-Robots-Tag',
        'X-Content-Type-Options',
        'ETag',
        'Last-Modified',
    ];

    /**
     * The subset of {@see self::PRESERVED_HEADERS} that `nginx-accel` must
     * re-emit inside the internal location, because nginx drops or overwrites
     * these and only these.
     *
     * 🛑 MEASURED on nginx 1.27.5, not derived. SPEC 18.18 records that nginx
     * "replaces the entire response header set" on an internal redirect, and
     * re-emitting the whole of PRESERVED_HEADERS on that basis is itself a
     * defect: `add_header` APPENDS, so a header nginx already kept is then sent
     * twice, and SPEC 8.9.8 requires each exactly once. That is not a cosmetic
     * fault — two `Cache-Control` headers are two policies, and which one a
     * cache obeys is its choice, not ours.
     *
     * SPEC 18.18 is right about the consequence and wrong about the mechanism.
     * Measured with the re-emission removed, a `members` document kept
     * `Cache-Control: no-store, private` and lost `CDN-Cache-Control` entirely:
     * a private document reaching a CDN with nothing on the CDN axis telling it
     * not to store, behind a correct-looking 200. That is SPEC 9.3.2 breaking
     * exactly where SPEC 18.18 said it would, for a different reason.
     *
     * @see self::NGINX_NATIVE_HEADERS for the complement, and why it is a
     *      declared decision rather than an omission.
     */
    public const NGINX_REEMITTED_HEADERS = [
        'CDN-Cache-Control',
        'Vary',
        'Cache-Tag',
        'Content-Security-Policy',
        'Content-Encoding',
        'Link',
        'X-Robots-Tag',
        'X-Content-Type-Options',
    ];

    /**
     * The complement: headers `nginx-accel` must NOT re-emit, each with the
     * measured reason.
     *
     * 🛑 Declared rather than left implicit, because the two constants together
     * must partition {@see self::PRESERVED_HEADERS} with nothing left over. A
     * test asserts that, which is what makes adding a header to PRESERVED_HEADERS
     * force a decision about nginx instead of silently defaulting to one. An
     * unclassified header is the SPEC 18.18 failure in its original form.
     *
     * - `Cache-Control`, `Content-Type`, `Content-Disposition` — nginx KEEPS the
     *   upstream value through the internal redirect. Re-emitting duplicates it.
     * - `ETag`, `Last-Modified` — nginx REPLACES these with the served file's
     *   own, and SPEC 8.9.8 wants precisely that: the handoff is what "buys
     *   ETags, If-None-Match and Range from the web server". Re-emitting the
     *   application's would send two ETags and break conditional requests,
     *   which is worse than either value alone.
     */
    public const NGINX_NATIVE_HEADERS = [
        'Cache-Control',
        'Content-Type',
        'Content-Disposition',
        'ETag',
        'Last-Modified',
    ];

    /** `caddy-intercept` or `nginx-accel`, for `X-DocUp-Resolver` and `doctor`. */
    public function driver(): string;

    /**
     * Hand one artifact object to the edge.
     *
     * @param  string  $storageKey  relative to the artifact root, e.g.
     *                              `builds/{uuid}/html/index.html`
     * @param  array<string, string>  $headers  the response headers the
     *                                          application decided; every one
     *                                          named in {@see self::PRESERVED_HEADERS}
     *                                          must reach the reader exactly once
     */
    public function respond(string $storageKey, array $headers): Response;
}
