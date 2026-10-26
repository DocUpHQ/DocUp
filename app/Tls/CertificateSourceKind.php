<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

/**
 * §8.10.14's four certificate sources.
 *
 * > "Four certificate sources MUST sit behind one contract: public ACME, an
 * > internal ACME directory (step-ca, Vault, ADCS) for air-gapped and
 * > corporate-PKI installations, operator-uploaded PEM, and a development
 * > issuer."
 *
 * 🛑 The enum names where a certificate **came from**, never where it is
 * served from. Anything that reaches the `certificates` table is served from
 * the database at handshake time, whichever case produced it — including a
 * public ACME certificate this installation issued itself. The other half of
 * §8.10.11's design is a custom domain whose certificate the **proxy**
 * obtains under the permission endpoint: there is no row for it, the handshake
 * endpoint answers 404, and the proxy falls back to its own on-demand
 * issuance. "No row" is the whole signal, which is why no enum case says it.
 */
enum CertificateSourceKind: string
{
    case PublicAcme = 'public_acme';
    case InternalAcme = 'internal_acme';
    case Uploaded = 'uploaded';
    case Development = 'development';

    /** Whether this source speaks ACME, and therefore needs an account. */
    public function isAcme(): bool
    {
        return $this === self::PublicAcme || $this === self::InternalAcme;
    }
}
