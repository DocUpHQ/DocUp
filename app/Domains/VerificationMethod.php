<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

/**
 * §8.10.4's three complementary mechanisms.
 *
 * "Complementary" rather than alternative: each covers a case the others
 * cannot. The parent claim is the only one that scales to a hundred
 * subdomains; the CNAME is the only one where the record is simultaneously
 * route and proof; the TXT is the only one an apex can use, because RFC 1034
 * forbids a CNAME beside a zone's SOA.
 *
 * The values match `domains.verification_method` and
 * `domain_verification_events.method`, and they are §8.1.11 public contract.
 */
enum VerificationMethod: string
{
    /** 🛑 Proven at the apex; every host under it binds with no further proof. */
    case ParentClaim = 'parent_claim';

    /** A `_docup-challenge.<host>` TXT record carrying the per-host token. */
    case DnsTxt = 'dns_txt';

    /** 🛑 An unguessable label under the documentation apex: route and proof in one. */
    case Cname = 'cname';
}
