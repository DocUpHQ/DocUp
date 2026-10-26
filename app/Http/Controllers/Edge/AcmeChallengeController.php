<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Edge;

use App\Tls\Acme\AcmeChallenges;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * RFC 8555 §8.3's `http-01` response, at §8.10.18's reserved path.
 *
 * 🛑 **Only the application's own challenges reach this controller.** When
 * the proxy obtains a certificate itself under §8.10.11, it answers its own
 * challenge below the route table and this is never called. What is left for
 * this controller is the case where DocUp is the ACME client — an internal
 * directory for an air-gapped installation (§8.10.14) — and that is the one
 * case where nothing else can answer.
 *
 * 🛑 **Public, unauthenticated, and that is the protocol.** The CA fetches
 * this over plain HTTP from an address nobody can predict, with no
 * credentials. What makes it safe is that the value is worthless without the
 * account key: a key authorization is `token.thumbprint`, the thumbprint is
 * of a public key, and the CA checks that the account presenting the order
 * is the one whose thumbprint appears. Serving it to the whole internet
 * proves nothing to anybody who is not already the account holder.
 */
final class AcmeChallengeController
{
    /**
     * 🛑 The token is read from the route, **never** taken as a positional
     * parameter, and that is a correctness fix rather than a style choice.
     *
     * `routes/edge.php` scopes this route to `Route::domain('{docupEdgeHost}')`
     * — it has to, or Laravel matches the documentation catch-all first — so
     * the route carries **two** parameters. Laravel hands a controller its
     * route parameters positionally after splicing container dependencies in
     * by reflection index, so a signature of `(string $token, AcmeChallenges
     * $challenges)` receives the **hostname** in `$token`. The lookup then
     * misses, the CA sees a 404, and every log line in the application looks
     * correct.
     *
     * Reading it by name cannot be wrong whatever parameters the route grows.
     */
    public function __invoke(Request $request, AcmeChallenges $challenges): Response
    {
        $token = $request->route('token');
        $answer = is_string($token) ? $challenges->answer($token) : null;

        if ($answer === null) {
            /*
             * 🛑 404 with an empty body, not a 200 with something
             * plausible. A CA treats any unexpected body as a failed
             * validation, and a failed validation costs authorization-failure
             * budget — five an hour per identifier, per §8.10.13's
             * circuit breaker — so an endpoint that guessed would spend a
             * budget it cannot see.
             */
            return new Response('', 404, ['Cache-Control' => 'no-store']);
        }

        return new Response($answer, 200, [
            /*
             * RFC 8555 §8.3 asks for `application/octet-stream` or no type
             * at all, and says a CA MUST ignore the type. `text/plain` is
             * what every other implementation sends and what a human
             * debugging with curl expects to read.
             */
            'Content-Type' => 'text/plain; charset=utf-8',
            'Cache-Control' => 'no-store',
        ]);
    }
}
