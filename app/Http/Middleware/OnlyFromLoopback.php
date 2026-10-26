<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Middleware;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * 🛑 §20.2's "internal, session-free edge endpoints", enforced in PHP.
 *
 * The permission endpoint tells anybody who can reach it which hostnames the
 * installation knows about; the certificate endpoint hands out **private
 * keys**. Neither has any authentication, because §8.10.11 requires the first
 * to be "session-free" and answer "in under 5 ms" — the proxy calls it during
 * a TLS handshake, before any session could exist.
 *
 * What takes authentication's place is the source address. The proxy and the
 * application are the same process in the shipped topology, so these requests
 * genuinely originate on loopback and nothing else legitimately does.
 *
 * 🛑 **`$request->ip()`, not a header.** §8.9.4 forbids a trusted
 * project-resolution request header "in any environment", and the same
 * reasoning is stronger here: an `X-Forwarded-For` that this middleware
 * believed would let anybody who can reach the application claim to be the
 * proxy and ask for a private key. Laravel's `ip()` returns the
 * `TrustProxies`-resolved client address, and the shipped configuration
 * trusts no proxy for this purpose.
 *
 * 🛑 **404, not 403.** A 403 confirms the endpoint exists. There is nothing to
 * gain from telling an unauthorised caller that they found the certificate
 * store.
 */
final class OnlyFromLoopback
{
    public function handle(Request $request, \Closure $next): Response
    {
        $ip = (string) $request->ip();

        if (! self::isLoopback($ip)) {
            /*
             * A bare response rather than `abort(404)`, which renders
             * Laravel's HTML error page. These are machine endpoints on the
             * handshake path: the caller reads a status code, and rendering
             * a stylesheet for it is work done on a request that should
             * cost as little as possible.
             */
            return new Response('', 404, ['Cache-Control' => 'no-store']);
        }

        return $next($request);
    }

    public static function isLoopback(string $ip): bool
    {
        $packed = @inet_pton($ip);

        if ($packed === false) {
            return false;
        }

        /*
         * The whole 127.0.0.0/8 block, not just 127.0.0.1: a container may
         * bind or connect on any of it, and `::1` is the IPv6 form. Compared
         * against packed bytes rather than strings, because `::ffff:127.0.0.1`
         * and `127.0.0.1` are one address spelled two ways and a string test
         * would accept one and refuse the other.
         */
        if (strlen($packed) === 4) {
            return $packed[0] === "\x7f";
        }

        if ($packed === inet_pton('::1')) {
            return true;
        }

        // IPv4-mapped IPv6: ::ffff:127.0.0.0/8
        return str_starts_with($packed, "\0\0\0\0\0\0\0\0\0\0\xff\xff") && $packed[12] === "\x7f";
    }
}
