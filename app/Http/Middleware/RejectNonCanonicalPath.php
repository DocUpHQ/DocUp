<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Serving\CanonicalPath;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * 🛑 §8.9.6 — the first thing on the documentation origin, and nothing may
 * precede it.
 *
 * §8.9.6: "Any request path not **byte-identical to its own canonical
 * normalisation** MUST be rejected with 400, **before any cache lookup or
 * resolution**. This is the web-cache-deception defence and **its position in
 * the pipeline is the whole of its value**."
 *
 * So this middleware is first in the documentation group, and the test that
 * matters asserts the ordering rather than the status code: a 400 returned after
 * a cache lookup satisfies the code and none of the requirement, because the
 * poisoned entry is already stored.
 *
 * 🛑 It reads the **raw** path, not Laravel's. `$request->path()` has already
 * been through the framework's own tidying, and §8.9.6's check is on the bytes
 * as they arrived — corpus case `path-002`'s note is explicit: "must be rejected
 * on the raw path, not after decoding". Reading a normalised path here would
 * check the normalisation against itself and pass everything.
 */
final class RejectNonCanonicalPath
{
    /** The header naming which rule answered, for an operator reading a log. */
    public const RESOLVER_HEADER = 'X-DocUp-Resolver';

    public function handle(Request $request, \Closure $next): Response
    {
        $raw = self::rawPath($request);
        $reason = CanonicalPath::reject($raw);

        if ($reason !== null) {
            /*
             * A bare 400 with no body. §9.3's rate-limiting notes name the
             * uncached-404 pattern as a denial-of-service shape, and the same
             * applies here: this path is reachable without limit by anyone, so
             * it must be the cheapest response the application can produce.
             * No view, no translation, no query.
             *
             * 🛑 `no-store` on the rejection too. A cached 400 keyed on a
             * non-canonical path would be a cache entry an attacker chose the
             * key of — which is the thing being defended against, arriving by
             * the defence.
             */
            return response('', 400, [
                self::RESOLVER_HEADER => $reason->value,
                'Cache-Control' => 'private, no-store',
                'CDN-Cache-Control' => 'private, no-store',
                'X-Content-Type-Options' => 'nosniff',
            ]);
        }

        return $next($request);
    }

    /**
     * The request path exactly as it arrived.
     *
     * From `REQUEST_URI` with the query string removed and nothing else done to
     * it. Laravel's `$request->path()` strips the leading slash, decodes, and
     * has already resolved the route — all three of which would defeat the
     * check.
     */
    public static function rawPath(Request $request): string
    {
        $uri = $request->server('REQUEST_URI');

        if (! is_string($uri) || $uri === '') {
            // No REQUEST_URI means this is not a real HTTP request — a console
            // run, or a synthetic one. `/` is canonical and harmless.
            return '/';
        }

        $query = strpos($uri, '?');

        return $query === false ? $uri : substr($uri, 0, $query);
    }
}
