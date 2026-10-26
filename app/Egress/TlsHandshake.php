<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Egress;

use App\Domains\DnsRecords;
use App\Tls\TlsProber;

/**
 * One outbound TLS handshake, as §8.10.17's prober needs it.
 *
 * The seam is here for the reason {@see Transport} and
 * {@see DnsRecords} have one: the fact under test in
 * {@see TlsProber} is **what DocUp records** about a handshake, and
 * arranging a real hostname that is verified, active and nevertheless
 * broken needs a listener, a DNS entry and a certificate authority that
 * refuses — a condition nobody can create on demand, and which would make
 * the test flaky if they could.
 *
 * 🛑 The seam is deliberately *below* everything that decides anything. An
 * implementation returns what the peer presented and nothing else; the
 * interpretation — trusted or not, expiring or not, worth a row or not —
 * is `TlsProber`'s and is exercised against the real class in CI.
 */
interface TlsHandshake
{
    /**
     * @return array{trusted: bool, error: string|null, certificate: array<array-key, mixed>|null}
     */
    public function probe(string $host, int $port = 443): array;
}
