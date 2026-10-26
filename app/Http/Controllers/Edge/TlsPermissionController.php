<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Edge;

use App\Http\Middleware\OnlyFromLoopback;
use App\Tls\IssuancePermission;
use App\Tls\PermissionVerdict;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * 🛑 §8.10.11's permission endpoint, as the proxy sees it.
 *
 * Caddy's on-demand TLS asks this URL with `?domain=<sni>` and reads **the
 * status code and nothing else**: 2xx authorises issuance, anything else
 * cancels it and fails the handshake. So the response body is empty, and
 * that is deliberate rather than lazy — see {@see PermissionVerdict}
 * for why the reason never crosses this boundary.
 *
 * 🛑 The whole decision is {@see IssuancePermission}'s, and this class adds
 * nothing to it. A controller that applied "just one more check" would be a
 * second place the policy lived, and the one that got forgotten when the
 * policy changed.
 */
final class TlsPermissionController
{
    public function __invoke(Request $request, IssuancePermission $permission): Response
    {
        $domain = $request->query('domain');

        /*
         * Fail closed on a missing or malformed parameter. Caddy always
         * sends it; anything that does not is not Caddy, and a request this
         * endpoint does not understand is one it must not authorise.
         */
        if (! is_string($domain) || $domain === '') {
            return self::deny();
        }

        return $permission->decide($domain)->permits()
            ? new Response('', 200, self::HEADERS)
            : self::deny();
    }

    /**
     * 🛑 403 rather than 404, and this is the one place the reasoning runs
     * the other way from {@see OnlyFromLoopback}.
     *
     * There, 404 hides the endpoint from a caller who should not have found
     * it. Here the caller is the proxy, which already knows the endpoint
     * exists because the operator configured it — so the only thing a status
     * code can do is distinguish "I am here and the answer is no" from "this
     * URL is wrong". A permission endpoint that 404s a denial is
     * indistinguishable from one that has been misconfigured out of
     * existence, and an operator debugging "no certificates are being
     * issued" cannot tell which.
     */
    private const array HEADERS = [
        'Cache-Control' => 'no-store',
        'Content-Type' => 'text/plain; charset=utf-8',
    ];

    private static function deny(): Response
    {
        return new Response('', 403, self::HEADERS);
    }
}
