<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

use Illuminate\Support\Carbon;

/**
 * What one outbound TLS handshake told us (§8.10.17).
 *
 * 🛑 Either `notAfter` and `issuer` are set, or `error` is. A probe that
 * reported both would be a probe whose caller had to decide which to
 * believe, and the decision would differ between the dashboard and the
 * alerting.
 */
final readonly class TlsProbe
{
    private function __construct(
        public string $host,
        public ?Carbon $notAfter,
        public ?string $issuer,
        public ?string $fingerprint,
        public ?string $error,
    ) {}

    public static function succeeded(string $host, Carbon $notAfter, string $issuer, string $fingerprint): self
    {
        return new self($host, $notAfter, $issuer, $fingerprint, null);
    }

    public static function failed(string $host, string $error): self
    {
        return new self($host, null, null, null, substr($error, 0, 255));
    }

    public function ok(): bool
    {
        return $this->error === null;
    }

    /** Whether the certificate is inside the renewal slack and nothing has renewed it. */
    public function expiringWithin(int $days, ?Carbon $now = null): bool
    {
        if ($this->notAfter === null) {
            return false;
        }

        return $this->notAfter->lessThanOrEqualTo(($now ?? Carbon::now())->copy()->addDays($days));
    }
}
