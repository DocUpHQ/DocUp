<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

use Symfony\Component\HttpFoundation\Response;

/**
 * The equal alternative edge driver (§11.3): nginx `X-Accel-Redirect` into an
 * `internal` location.
 *
 * 🛑 **This driver carries a compensating control, and it is mandatory.**
 * §18.18, measured in ADR 0001: nginx-accel "**replaces the entire response
 * header set**, dropping the application's `Cache-Control: private, no-store`,
 * `Vary: Cookie`, CSP, `Link` and `X-Robots-Tag`." So the application's headers
 * must be re-emitted inside the internal location, from the upstream response.
 *
 * Without re-emission a private document is served with no `private, no-store`
 * and no `Vary: Cookie`. §9.3.2's failure, arriving silently behind a
 * correct-looking 200 — which is why §18.18's pre-decided mitigation is "guarded
 * by a **permanent** integration test", and why
 * {@see ArtifactHandoff::PRESERVED_HEADERS} is asserted against
 * `deploy/nginx.conf` rather than trusted.
 *
 * **What this class does and does not fix.** It sets the same headers as the
 * Caddy driver, because nginx reads them from the upstream response as
 * `$upstream_http_*`. It cannot make nginx emit a header the configuration does
 * not name — that list lives in `deploy/nginx.conf` and is the thing the test
 * keeps honest. So the driver is thin and the control is structural, which is
 * the right way round: a driver that tried to compensate in PHP would be
 * pretending it could.
 */
final class NginxAccelHandoff implements ArtifactHandoff
{
    public function driver(): string
    {
        return 'nginx-accel';
    }

    public function respond(string $storageKey, array $headers): Response
    {
        $response = new Response('', Response::HTTP_OK);

        $response->headers->set('X-Accel-Redirect', self::INTERNAL_PREFIX.'/'.ltrim($storageKey, '/'));

        /*
         * 🛑 Buffering off, and this is not a performance tweak.
         *
         * With `X-Accel-Buffering: no` nginx streams the file rather than
         * buffering it, which is what keeps memory flat on a 500 MB artifact —
         * Phase 04's exit criterion. ADR 0001 measured the handoff with PHP's
         * `memory_limit` at 16M; the limit on the edge side is nginx's
         * `proxy_buffers`, and a large buffered response is the one place the
         * flat-memory claim could still fail after the bytes have left PHP.
         */
        $response->headers->set('X-Accel-Buffering', 'no');

        foreach ($headers as $name => $value) {
            $response->headers->set($name, $value);
        }

        // See the Caddy driver: the application has not read the bytes, so it
        // does not know their length and must not claim to.
        $response->headers->remove('Content-Length');

        return $response;
    }
}
