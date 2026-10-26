<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

/**
 * §8.10.14's one contract.
 *
 * > "Four certificate sources MUST sit behind one contract: public ACME, an
 * > internal ACME directory (step-ca, Vault, ADCS) for air-gapped and
 * > corporate-PKI installations, operator-uploaded PEM, and a development
 * > issuer."
 *
 * 🛑 The contract is deliberately this narrow. Everything that differs
 * between an air-gapped step-ca, a public CA and a self-signed development
 * certificate is *inside* an implementation; everything the rest of the
 * application needs is a chain, a key and the hostname they are for. A
 * contract that leaked the difference — a `challengeType()`, a
 * `requiresDns()` — would push the four sources' differences out into every
 * caller, and the next source would change all of them.
 *
 * An uploaded certificate is a source in exactly the same sense: the
 * operator's paste is its "issuance", which is why {@see UploadedCertificateSource}
 * takes the PEM in its constructor rather than fetching anything.
 */
interface CertificateSource
{
    public function kind(): CertificateSourceKind;

    /**
     * Produce a certificate for one hostname.
     *
     * @param  string  $host  normalised punycode A-labels (§8.10.7)
     *
     * @throws CertificateRefused when this source cannot produce one. Never
     *                            returns null: "no certificate" from a source
     *                            that was asked for one is a fault with a
     *                            cause, and a null would discard the cause.
     */
    public function issue(string $host): IssuedCertificate;
}
