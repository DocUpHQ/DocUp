<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Edge;

use App\Domains\Hostname;
use App\Tls\CertificateRefused;
use App\Tls\CertificateStore;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * 🛑 §8.10.14's handshake-time certificate endpoint.
 *
 * > "Uploaded and internal-PKI certificates MUST be delivered to the edge
 * > **at handshake time from the database**, not by writing files or calling
 * > a proxy admin API, so they replicate to every replica with no shared
 * > storage. The proxy admin API MUST stay **disabled** — it is
 * > root-equivalent on the edge."
 *
 * Caddy's `get_certificate http` calls this with `?server_name=<sni>` and
 * expects **200 with a PEM chain and key** or nothing it can use.
 *
 * 🛑 **"I have none" is `204 No Content`, and it is NOT `404`.** This is
 * §18.17 — "the edge … falls back to on-demand ACME on a negative answer,
 * rather than failing the handshake" — and Phase 19 measured it against a
 * running Caddy instead of assuming it. The two negative answers behave
 * completely differently and Caddy's documentation describes neither:
 *
 *   `404` → `tls.handshake: external certificate manager … got HTTP 404`,
 *           and the handshake is **failed**. No ACME attempt is made, ever.
 *   `204` → the manager is treated as having nothing, Caddy falls through to
 *           on-demand issuance, solves the challenge and serves the result.
 *
 * So the obvious implementation — 404 for a name we hold nothing for — would
 * have left every custom domain's on-demand issuance broken, with this
 * endpoint looking correct, the permission endpoint answering 200, and the
 * only symptom a TLS error at the reader. §18.17's pre-decided consequence
 * was two host-list-selected TLS policies and a debounced config render for
 * BYO hosts, which would have cost §8.10.16's "no reload". It is not
 * needed: the assumption holds, on 204.
 *
 * 🛑 So a negative answer here is a **normal** answer, and the common one:
 * §8.10.11's design has the proxy obtain most custom domains' certificates
 * itself, so most hostnames have no row and never will.
 */
final class TlsCertificateController
{
    public function __invoke(Request $request, CertificateStore $store): Response
    {
        $name = $request->query('server_name');

        if (! is_string($name) || $name === '') {
            return self::absent();
        }

        try {
            $host = Hostname::normalise($name);
        } catch (\Throwable) {
            /*
             * An SNI value that is not a hostname cannot match a stored
             * certificate, and normalising is also what stops an unvalidated
             * remote string reaching a query. Absent, like any other name
             * we hold nothing for.
             */
            return self::absent();
        }

        $certificate = $store->activeFor($host);

        if ($certificate === null) {
            return self::absent();
        }

        /*
         * 🛑 Expiry is checked here as well as by §8.10.17's prober. The
         * prober runs every six hours; a certificate that expired between
         * two runs would otherwise be handed to the proxy, which would serve
         * it, and every reader would see an expiry warning while the
         * installation believed it was healthy. Withholding it makes the
         * proxy fall back to issuance, which is the recovery.
         */
        if ($certificate->not_after->isPast()) {
            return self::absent();
        }

        try {
            $pem = $store->pem($certificate);
        } catch (CertificateRefused) {
            return self::absent();
        }

        return new Response($pem, 200, [
            'Content-Type' => 'application/x-pem-file',
            /*
             * 🛑 `no-store`, on a response that contains a private key.
             * Nothing between this endpoint and the proxy should hold it,
             * and in the shipped topology nothing is — but this header is
             * what keeps that true if an operator ever puts something there.
             */
            'Cache-Control' => 'no-store',
        ]);
    }

    /**
     * 🛑 204, never 404. The class docblock has the measurement: a 404 makes
     * Caddy fail the handshake instead of falling back to issuance, and
     * nothing in its documentation says so.
     */
    private static function absent(): Response
    {
        return new Response('', 204, ['Cache-Control' => 'no-store']);
    }
}
