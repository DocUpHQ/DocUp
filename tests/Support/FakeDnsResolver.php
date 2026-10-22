<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Support;

use App\Egress\DnsResolver;
use App\Egress\ResolvedHost;

/**
 * A resolver that answers from a script, so DNS rebinding can be exercised.
 *
 * 🛑 This is the only way to test the rebind control honestly. A real rebind
 * needs an authoritative nameserver that answers differently on consecutive
 * queries; standing one up inside the suite would make the test slow, flaky
 * and dependent on the runner's resolver honouring a TTL of 0 — three good
 * reasons for the test to be deleted the first time CI goes amber. The fact
 * under test is "the second answer disagrees with the first", and that is
 * exactly what this models.
 *
 * Answers are consumed in order; the last one repeats, so a name with a single
 * scripted answer is stable.
 */
final class FakeDnsResolver implements DnsResolver
{
    /** @var array<string, list<ResolvedHost>> */
    private array $script = [];

    /** @var array<string, int> */
    private array $calls = [];

    /**
     * Answer this name with the same addresses every time.
     *
     * @param  list<string>  $addresses
     */
    public function stable(string $host, array $addresses, ?int $ttl = 300): self
    {
        $this->script[strtolower($host)] = [new ResolvedHost($addresses, $ttl)];

        return $this;
    }

    /**
     * Answer this name differently on the second and subsequent lookups —
     * the TTL-0 rebind shape.
     *
     * @param  list<string>  $first
     * @param  list<string>  $then
     */
    public function rebinding(string $host, array $first, array $then): self
    {
        $this->script[strtolower($host)] = [
            new ResolvedHost($first, 0),
            new ResolvedHost($then, 0),
        ];

        return $this;
    }

    /** A name with no address records. */
    public function unresolvable(string $host): self
    {
        $this->script[strtolower($host)] = [ResolvedHost::none()];

        return $this;
    }

    public function resolve(string $host): ResolvedHost
    {
        $host = strtolower($host);
        $answers = $this->script[$host] ?? null;

        if ($answers === null) {
            return ResolvedHost::none();
        }

        $index = $this->calls[$host] ?? 0;
        $this->calls[$host] = $index + 1;

        return $answers[min($index, count($answers) - 1)];
    }

    /** How many times a name was looked up — the pin is only real if this is bounded. */
    public function callsFor(string $host): int
    {
        return $this->calls[strtolower($host)] ?? 0;
    }
}
