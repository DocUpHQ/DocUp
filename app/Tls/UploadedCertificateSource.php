<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

use Illuminate\Support\Carbon;

/**
 * §8.10.14's third source: a PEM pair the operator supplied.
 *
 * There is nothing to fetch, so "issuance" is validation. What makes this a
 * source rather than a setter is that the validation is the same validation
 * every other source's output goes through, and the result lands in the same
 * table and is served by the same handshake endpoint. An upload path that
 * wrote the row directly would be the one path whose certificate nobody had
 * checked covered its hostname.
 */
final readonly class UploadedCertificateSource implements CertificateSource
{
    public function __construct(
        private string $chainPem,
        private string $privateKeyPem,
        private ?Carbon $now = null,
    ) {}

    public function kind(): CertificateSourceKind
    {
        return CertificateSourceKind::Uploaded;
    }

    public function issue(string $host): IssuedCertificate
    {
        $certificate = IssuedCertificate::fromPem($this->chainPem, $this->privateKeyPem);

        /*
         * 🛑 The two checks an upload needs and an ACME exchange does not,
         * because the CA has already made both true for itself.
         *
         * A chain that does not cover the hostname fails at handshake, on the
         * live site, with nothing in this application's logs. An expired one
         * fails the same way. Both are ordinary operator mistakes — a
         * wildcard pasted onto the wrong host, a renewal that sat in a ticket
         * for a fortnight — and both are cheap to refuse here.
         */
        if (! $certificate->covers($host)) {
            throw CertificateRefused::of(
                CertificateRejection::HostNotCovered,
                $host.' is not among '.implode(', ', $certificate->names),
            );
        }

        $now = $this->now ?? Carbon::now();

        if ($now->lessThan($certificate->notBefore) || $now->greaterThanOrEqualTo($certificate->notAfter)) {
            throw CertificateRefused::of(
                CertificateRejection::OutsideValidity,
                $certificate->notBefore->toDateTimeString().' .. '.$certificate->notAfter->toDateTimeString(),
            );
        }

        return $certificate;
    }
}
