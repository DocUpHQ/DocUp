<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

use App\Egress\EgressRefused;
use App\Egress\HardenedEgressClient;

/**
 * A resolver that asks one DNS-over-HTTPS provider (§8.10.6).
 *
 * 🛑 **DoH rather than the system resolver, and that is the SSRF hardening
 * the requirement asks for.** §8.10.6 wants "at least two independent
 * resolvers that must agree, SSRF-hardened": the system stub answers from
 * whatever `/etc/resolv.conf` names, which inside a container is the
 * runtime's own resolver — one answer, from a resolver the installation does
 * not control, over a path {@see HardenedEgressClient} cannot see. Asking two
 * named providers over HTTPS makes "independent" true rather than hoped for,
 * and puts every byte through the guard that already refuses private and
 * link-local destinations.
 *
 * 🛑 The provider is reached through `HardenedEgressClient`, never through
 * curl directly, because §4.3/7 gives outbound HTTP exactly one call site and
 * an architecture test enforces it.
 */
final readonly class DohRecords implements DnsRecords
{
    /** RFC 1035 record types, for the `type` query parameter. */
    private const TYPE_TXT = 16;

    private const TYPE_CNAME = 5;

    private const TYPE_A = 1;

    private const TYPE_AAAA = 28;

    public function __construct(
        private HardenedEgressClient $client,
        private string $endpoint,
        private string $label,
    ) {}

    public function name(): string
    {
        return $this->label;
    }

    public function txt(string $name): ?array
    {
        $answers = $this->query($name, self::TYPE_TXT);

        if ($answers === null) {
            return null;
        }

        $values = [];

        foreach ($answers as $answer) {
            /*
             * A TXT record's value arrives quoted, and a long one arrives as
             * several quoted strings that the protocol concatenates. Both
             * spellings reach us as one field, so the quotes come out and
             * the pieces join — a token split at 255 bytes would otherwise
             * never match, which is a failure mode that only appears once a
             * token is long enough.
             */
            $values[] = str_replace(['" "', '"'], '', $answer);
        }

        return $values;
    }

    public function cname(string $name): ?string
    {
        $answers = $this->query($name, self::TYPE_CNAME);

        if ($answers === null) {
            return null;
        }

        // Trailing dot removed: the wire form is fully qualified and the
        // configured target is not, and two spellings of one name must
        // compare equal.
        return $answers === [] ? '' : rtrim(strtolower($answers[0]), '.');
    }

    public function addresses(string $name): ?array
    {
        $v4 = $this->query($name, self::TYPE_A);
        $v6 = $this->query($name, self::TYPE_AAAA);

        /*
         * 🛑 Both queries must have been answered before this is an answer.
         *
         * A host with only AAAA records answers the A query with an empty
         * list and the AAAA query with addresses; a resolver that was down
         * for the AAAA query would then look like a host with no IPv6 — and
         * §8.10.11's permission check would refuse a hostname that is
         * correctly configured. Null for either is null for the pair, which
         * {@see AgreeingResolvers} reads as "did not answer" rather than as
         * "does not point here".
         */
        if ($v4 === null || $v6 === null) {
            return null;
        }

        $addresses = [];

        foreach ([...$v4, ...$v6] as $address) {
            $normalised = self::normaliseAddress($address);

            if ($normalised !== null && ! in_array($normalised, $addresses, true)) {
                $addresses[] = $normalised;
            }
        }

        return $addresses;
    }

    /**
     * 🛑 Parsed and re-emitted, never compared as the provider spelled it.
     *
     * Two DoH providers may return `2001:db8::1` and `2001:0db8:0:0:0:0:0:1`
     * for one address, and a string comparison would call a correctly
     * pointed host misconfigured. `inet_pton` then `inet_ntop` gives one
     * spelling per address, and refuses anything that is not an address at
     * all — which is also the validation this value needs, since it came
     * from a remote JSON document.
     */
    private static function normaliseAddress(string $address): ?string
    {
        $packed = @inet_pton(trim($address));

        if ($packed === false) {
            return null;
        }

        $printable = @inet_ntop($packed);

        return is_string($printable) ? $printable : null;
    }

    /**
     * One DoH query, returning the answer data or null when the provider did
     * not answer usefully.
     *
     * @return list<string>|null
     */
    private function query(string $name, int $type): ?array
    {
        $url = $this->endpoint.'?name='.rawurlencode($name).'&type='.$type;

        try {
            $response = $this->client->get($url, ['Accept' => 'application/dns-json']);
        } catch (EgressRefused) {
            /*
             * The guard refused the provider itself — a misconfigured
             * endpoint, or one that resolved somewhere private. Null, not an
             * exception: this is one of two resolvers and the caller's job is
             * to notice that it did not answer.
             */
            return null;
        }

        if (! $response->successful()) {
            return null;
        }

        $payload = json_decode($response->body, true);

        if (! is_array($payload)) {
            return null;
        }

        /*
         * `Status` is the DNS RCODE. 0 is NOERROR and 3 is NXDOMAIN, and
         * those are the only two that tell us anything: NXDOMAIN means the
         * name does not exist, which is a *failed proof* rather than a
         * failed lookup, so it answers with an empty list. Everything else —
         * SERVFAIL, REFUSED — is this resolver declining to answer.
         */
        $status = $payload['Status'] ?? null;

        if ($status === 3) {
            return [];
        }

        if ($status !== 0) {
            return null;
        }

        $answers = [];

        foreach (is_array($payload['Answer'] ?? null) ? $payload['Answer'] : [] as $answer) {
            if (! is_array($answer) || ($answer['type'] ?? null) !== $type) {
                continue;
            }

            if (is_string($answer['data'] ?? null)) {
                $answers[] = $answer['data'];
            }
        }

        return $answers;
    }
}
