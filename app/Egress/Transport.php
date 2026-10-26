<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Egress;

/**
 * The wire, with the connection address already decided.
 *
 * The seam is here and not higher because everything above it — scheme,
 * address policy, rebind detection, redirect refusal, the byte cap — is
 * decided from data and must run identically whatever carries the bytes. What
 * is left below the seam is one job: connect to **this** address, send the
 * original `Host`, and stop at the cap.
 */
interface Transport
{
    /**
     * @param  array<string, string>  $headers
     * @param  string|null  $body  the request body, or null for a request that
     *                             carries none. Added in Phase 19: ACME is a
     *                             POST-only protocol (RFC 8555 §6.3 even reads
     *                             GETs as POSTs with an empty payload), so a
     *                             client that could only GET could not speak
     *                             it — and §8.3.9's "one class, sole call
     *                             site" means the answer is a body here, not a
     *                             second client over there.
     *
     * @throws EgressRefused on timeout, byte cap or any transport failure
     */
    public function send(
        string $method,
        string $url,
        string $host,
        int $port,
        string $pinnedAddress,
        array $headers,
        EgressOptions $options,
        ?string $body = null,
    ): EgressResponse;
}
