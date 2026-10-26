<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

/**
 * §8.10.14's fourth source: a self-signed certificate, for development.
 *
 * 🛑 **Refused outside a local environment**, and the refusal is in the
 * constructor rather than in `issue()` so that a production container cannot
 * even hold one. §20.4's invariant is that no security control sits behind a
 * flag that defaults open; the cheapest reading of that here is that this
 * source has no flag at all. An operator who wants a certificate they signed
 * themselves uploads it (§8.10.14's third source) or runs an internal ACME
 * directory (its second) — both of which are real PKI with a real trust
 * decision behind them.
 *
 * What it is for: `docup:install` on a laptop, the integration tests in this
 * repository, and §8.10.17's prober having something to probe.
 */
final readonly class DevelopmentCertificateSource implements CertificateSource
{
    /** Short enough that nobody is tempted to leave one serving. */
    public const int LIFETIME_DAYS = 30;

    public function __construct(private string $environment)
    {
        if (! in_array($environment, ['local', 'testing'], true)) {
            throw CertificateRefused::of(
                CertificateRejection::AcmeRefused,
                'the development issuer is not available in the '.$environment.' environment',
            );
        }
    }

    public function kind(): CertificateSourceKind
    {
        return CertificateSourceKind::Development;
    }

    public function issue(string $host): IssuedCertificate
    {
        [$chain, $key] = Csr::selfSigned($host, Csr::key(), self::LIFETIME_DAYS);

        return IssuedCertificate::fromPem($chain, $key);
    }
}
