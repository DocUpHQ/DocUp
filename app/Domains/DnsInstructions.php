<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

use App\Models\Domain;
use App\Support\Uuid;

/**
 * 🛑 §8.10.8's per-case DNS instructions: the exact records to publish.
 *
 * > "The system MUST support apex domains and MUST publish per-case DNS
 * > instructions (CNAME, ALIAS/ANAME, A/AAAA). A self-hoster with a fixed IP
 * > can use A records, which is a genuine advantage over Read the Docs; say
 * > so."
 *
 * The phase's first exit criterion is "**see the exact CNAME and TXT
 * records**", which is a claim about this class: an operator who copies what
 * it returns must pass verification, and the verifier must check exactly
 * what it showed. So the two read one source — {@see Challenge} — and a test
 * asserts a domain verifies against the instructions it was given rather
 * than against values the test wrote out again.
 *
 * 🛑 An apex cannot carry a CNAME: RFC 1034 forbids a CNAME coexisting with
 * the SOA and NS records every zone apex has. That is why the apex case is a
 * different case rather than the same advice with a different name, and why
 * the A/AAAA option exists at all.
 */
final readonly class DnsInstructions
{
    /**
     * @param  list<array{type: string, name: string, value: string, note: string}>  $records
     * @param  list<array{type: string, name: string, value: string, note: string}>  $alternatives
     */
    public function __construct(
        public string $host,
        public bool $isApex,
        public array $records,
        public array $alternatives,
    ) {}

    /**
     * What to publish for this domain.
     *
     * @param  list<string>  $ingressAddresses  the installation's advertised A/AAAA targets
     */
    public static function for(Domain $domain, string $docsApex, array $ingressAddresses = []): self
    {
        $host = $domain->host;
        $isApex = Hostname::looksLikeApex($host);
        $target = Challenge::cnameTarget(Uuid::toBytes($domain->id), $docsApex);
        $token = (string) $domain->verification_token;

        $proof = [
            'type' => 'TXT',
            'name' => Challenge::txtName($host),
            'value' => $token,
            'note' => 'Proof of control. Keep it published: §8.10.6 re-verifies daily.',
        ];

        if (! $isApex) {
            /*
             * The one-record case, and the one to lead with. §8.10.4 makes
             * this CNAME "simultaneously route and proof", so an operator who
             * publishes it is finished — no TXT, no second step, nothing to
             * forget. The TXT below is offered as an alternative rather than
             * listed beside it, because showing two records when one will do
             * is how an operator concludes both are required.
             */
            return new self($host, false, [[
                'type' => 'CNAME',
                'name' => $host,
                'value' => $target,
                'note' => 'Route and proof in one record (§8.10.4). Nothing else is needed.',
            ]], [$proof]);
        }

        /*
         * The apex case. A CNAME is illegal here, so routing and proof
         * separate: the TXT proves control and an ALIAS/ANAME or A/AAAA
         * carries the traffic.
         */
        $alternatives = [[
            'type' => 'ALIAS',
            'name' => $host,
            'value' => $docsApex,
            'note' => 'ALIAS or ANAME, if your DNS provider offers one. It tracks our address changes.',
        ]];

        foreach ($ingressAddresses as $address) {
            $alternatives[] = [
                'type' => str_contains($address, ':') ? 'AAAA' : 'A',
                'name' => $host,
                'value' => $address,
                /*
                 * §8.10.8 asks for this to be said out loud, and it is worth
                 * saying: a hosted service cannot offer it, because its
                 * addresses are not yours to depend on. A self-hoster's are.
                 */
                'note' => 'A self-hosted installation has a fixed address, so plain A/AAAA records work '
                    .'— an option a hosted documentation service cannot offer you.',
            ];
        }

        return new self($host, true, [$proof], $alternatives);
    }

    /**
     * The records as the API and the dashboard render them.
     *
     * @return array{host: string, apex: bool, required: list<array{type: string, name: string, value: string, note: string}>, alternatives: list<array{type: string, name: string, value: string, note: string}>}
     */
    public function toArray(): array
    {
        return [
            'host' => $this->host,
            'apex' => $this->isApex,
            'required' => $this->records,
            'alternatives' => $this->alternatives,
        ];
    }
}
