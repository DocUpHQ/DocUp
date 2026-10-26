<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Support;

use App\Domains\DnsRecords;

/**
 * A resolver that answers from a script (§8.10.6).
 *
 * 🛑 The only honest way to test two resolvers that must agree. The fact
 * under test is "one resolver sees a record the other does not", and
 * reproducing it against real DNS needs two recursive resolvers in
 * disagreement — a condition nobody can arrange on demand and which would
 * make the test flaky if they could.
 *
 * Three answer shapes, matching the interface's three states: a list is an
 * answer, `[]` is "the name exists with no such record", and `null` is "this
 * resolver did not answer at all". The last is the one that matters, because
 * §8.10.6's state machine must not move on a resolver outage.
 */
final class FakeDnsRecords implements DnsRecords
{
    /** @var array<string, list<string>|null> */
    private array $txt = [];

    /** @var array<string, string|null> */
    private array $cname = [];

    /** @var array<string, list<string>|null> */
    private array $addresses = [];

    public function __construct(private readonly string $label = 'fake') {}

    public function name(): string
    {
        return $this->label;
    }

    /** @param  list<string>|null  $values */
    public function withTxt(string $name, ?array $values): self
    {
        $this->txt[$name] = $values;

        return $this;
    }

    /** `''` answers "no CNAME"; `null` answers "this resolver is down". */
    public function withCname(string $name, ?string $target): self
    {
        $this->cname[$name] = $target;

        return $this;
    }

    /**
     * §8.10.11's live-DNS check. `null` is a resolver outage for this name.
     *
     * @param  list<string>|null  $addresses
     */
    public function withAddresses(string $name, ?array $addresses): self
    {
        $this->addresses[$name] = $addresses;

        return $this;
    }

    /** Answer nothing at all, for every name: a resolver outage. */
    public function down(): self
    {
        $this->txt = [];
        $this->cname = [];
        $this->addresses = [];

        return $this;
    }

    public function txt(string $name): ?array
    {
        /*
         * An unscripted name answers with an empty list rather than null:
         * "this name has no TXT record" is the normal case in these tests,
         * and making the resolver appear down by default would turn every
         * missing-proof test into an unresolvable one.
         */
        return array_key_exists($name, $this->txt) ? $this->txt[$name] : [];
    }

    public function cname(string $name): ?string
    {
        return array_key_exists($name, $this->cname) ? $this->cname[$name] : '';
    }

    public function addresses(string $name): ?array
    {
        /*
         * An unscripted name resolves to nothing, for the reason `txt()`
         * gives: "this name has no address" is the normal case in these
         * tests — it is every bogus SNI in §19's 500-handshake criterion —
         * and making the resolver appear down by default would turn each of
         * them into an unresolvable check instead of a refused one.
         */
        return array_key_exists($name, $this->addresses) ? $this->addresses[$name] : [];
    }
}
