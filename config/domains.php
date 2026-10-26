<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

/*
|------------------------------------------------------------------------------
| Domain verification (SPEC 8.10)
|------------------------------------------------------------------------------
| 🛑 SPEC 8.10.6: "re-verified daily with exponential backoff against at least
| two independent resolvers that must agree, SSRF-hardened, rejecting private
| and link-local answers."
|
| "Independent" is the hard word. A container's system resolver is one answer
| from a resolver the installation does not control, over a path the SPEC 8.3.9
| egress guard cannot see. Two named DNS-over-HTTPS providers make independence
| true rather than hoped for, and every byte goes through HardenedEgressClient,
| which already refuses private and link-local destinations.
|
| 🛑 Two is a FLOOR, not a target. Adding a third only makes agreement stricter,
| which is the safe direction: AgreeingResolvers requires every answering
| resolver to agree, so a third that disagrees refuses the proof rather than
| outvoting anybody.
*/

return [

    /*
     * The DoH endpoints, keyed by the label that appears in a verification
     * event's `observed` map. Both must answer and agree before a proof is
     * accepted; fewer than two answers is `unresolvable`, which deliberately
     * moves no domain's state.
     *
     * Set DOCUP_DNS_RESOLVERS to a comma-separated `label=url` list to replace
     * them — an air-gapped installation points both at its own resolver, and
     * accepts that "independent" then means "asked twice".
     */
    'resolvers' => (static function (): array {
        $configured = env('DOCUP_DNS_RESOLVERS');

        if (! is_string($configured) || trim($configured) === '') {
            return [
                'cloudflare' => 'https://cloudflare-dns.com/dns-query',
                'google' => 'https://dns.google/resolve',
            ];
        }

        $resolvers = [];

        foreach (explode(',', $configured) as $entry) {
            $parts = explode('=', trim($entry), 2);

            if (count($parts) === 2 && $parts[0] !== '' && $parts[1] !== '') {
                $resolvers[$parts[0]] = $parts[1];
            }
        }

        return $resolvers;
    })(),

    /*
     * SPEC 8.10.8's A/AAAA option: the installation's advertised ingress
     * addresses, shown in the apex DNS instructions.
     *
     * Empty by default and that is honest — DocUp cannot discover its own
     * public address, and guessing it from a request would print whatever
     * the last proxy hop happened to be. An operator who sets this gets the
     * A-record advice SPEC 8.10.8 calls "a genuine advantage over Read the
     * Docs"; one who does not gets the CNAME and ALIAS cases, which work
     * everywhere.
     */
    'ingress_addresses' => array_values(array_filter(
        array_map('trim', explode(',', (string) env('DOCUP_INGRESS_ADDRESSES', ''))),
        static fn (string $address): bool => $address !== '',
    )),

];
