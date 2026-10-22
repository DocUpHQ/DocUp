<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

use Symfony\Component\HttpFoundation\Response;

/**
 * The default edge driver (§11.3): FrankenPHP/Caddy's `intercept` handler.
 *
 * 🛑 Default on one specific measured ground, not on preference. §11.3: "it
 * **preserves the application's response headers through the handoff
 * natively**, where nginx replaces the entire set and needs a hand-maintained
 * re-emission list to avoid serving private documents cacheable."
 *
 * So this driver sets the headers and trusts the edge with them, and that trust
 * is what ADR 0001 verified. The permanent header test still runs against this
 * driver — §8.9.8 requires it "on **every** driver in the CI matrix" — because
 * "preserves them natively" is a property of a Caddy version, not a law.
 *
 * Caddy legitimately adds its own `Vary: Accept-Encoding` alongside the
 * application's `Vary`, which is why §8.9.8 permits "multiple `Vary` headers
 * with **distinct** values, which are a semantic union". The test asserts
 * distinctness rather than a single occurrence for exactly this reason.
 */
final class CaddyInterceptHandoff implements ArtifactHandoff
{
    public function driver(): string
    {
        return 'caddy-intercept';
    }

    public function respond(string $storageKey, array $headers): Response
    {
        /*
         * An empty body with a 200 and the handoff header. Caddy's `intercept`
         * matches on the header's presence, replaces the body with the file,
         * and keeps these headers.
         *
         * 🛑 `X-Accel-Redirect` is also the header the Caddyfile strips from
         * the final response (`header -X-Accel-Redirect`), so the internal path
         * never reaches the reader. The storage layout is not secret, but a
         * reader who can see it can probe it — and §8.9.8 requires the internal
         * location to be externally unreachable, which is easier to keep true
         * when nobody has been handed its address.
         */
        $response = new Response('', Response::HTTP_OK);

        $response->headers->set('X-Accel-Redirect', self::INTERNAL_PREFIX.'/'.ltrim($storageKey, '/'));

        foreach ($headers as $name => $value) {
            $response->headers->set($name, $value);
        }

        /*
         * Content-Length is deliberately NOT set. The edge serves a file whose
         * length it knows, and a stale or guessed length from the application
         * would either truncate the response or hang the connection — and the
         * whole point of §8.9.8 is that the application has not read the bytes
         * and therefore does not know.
         */
        $response->headers->remove('Content-Length');

        return $response;
    }
}
