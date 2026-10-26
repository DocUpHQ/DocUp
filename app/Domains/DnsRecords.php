<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

/**
 * One resolver, for the record types §8.10.4's proofs are published in.
 *
 * Separate from `App\Egress\DnsResolver`, which answers "every address this
 * name resolves to" for §8.3.9's resolve-then-pin. That one exists to stop
 * the application connecting somewhere it should not; this one exists to read
 * what an operator published. Folding them together would give the SSRF guard
 * a TXT lookup it has no use for and give verification an address list it
 * cannot interpret.
 *
 * 🛑 Implementations MUST NOT throw on NXDOMAIN, SERVFAIL or a timeout. An
 * absent record and an unreachable resolver are different facts and
 * {@see AgreeingResolvers} distinguishes them, so an exception here would be
 * caught and flattened at the one place the difference mattered.
 */
interface DnsRecords
{
    /** How this resolver is named in a verification event. */
    public function name(): string;

    /**
     * Every TXT string at this name, or null when the resolver could not
     * answer at all.
     *
     * An empty list is "the name exists and has no TXT record", which is a
     * failed proof. Null is "this resolver did not answer", which is not.
     *
     * @return list<string>|null
     */
    public function txt(string $name): ?array;

    /**
     * The CNAME target at this name, `null` for no answer from the resolver,
     * and `''` for "answered, no CNAME".
     *
     * Three states rather than two, for the reason `txt()` has them.
     */
    public function cname(string $name): ?string;

    /**
     * Every A and AAAA address this name resolves to, or null when the
     * resolver could not answer at all.
     *
     * 🛑 Added in Phase 19 for §8.10.11, which gates on-demand issuance on a
     * hostname that "**currently resolves in live DNS to an advertised
     * ingress target**". That is the check which stops a tenant pointing a
     * hostname at the installation, proving control, moving the DNS
     * somewhere else, and keeping a certificate for a name they no longer
     * direct — and it is a check Phase 18's TXT and CNAME lookups could not
     * express, because a CNAME is only one of the three shapes §8.10.8
     * documents.
     *
     * The three states carry the same meanings as `txt()`: a list is an
     * answer, `[]` is "the name exists with no address", and null is "this
     * resolver did not answer", which must never be read as "the name does
     * not point here".
     *
     * @return list<string>|null
     */
    public function addresses(string $name): ?array;
}
