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
