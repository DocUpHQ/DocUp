<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Egress;

/**
 * One DNS answer: the addresses, and the shortest TTL among them.
 *
 * The TTL is carried because §18's rebind case is described as "TTL-0" and an
 * operator reading a refusal wants to see it. 🛑 It is **not** what the
 * detection depends on — see {@see EgressRejection::DnsRebindDetected}. A
 * hostile resolver sets whatever TTL it likes, so a control keyed on the TTL
 * is a control the attacker configures.
 */
final readonly class ResolvedHost
{
    /** @param  list<string>  $addresses  literal IPv4 and IPv6 addresses, in answer order */
    public function __construct(
        public array $addresses,
        public ?int $ttl = null,
    ) {}

    public static function none(): self
    {
        return new self([], null);
    }

    public function isEmpty(): bool
    {
        return $this->addresses === [];
    }

    /**
     * The answer as an order-insensitive set, for comparing two resolutions.
     *
     * @return array<string, true>
     */
    public function asSet(): array
    {
        $set = array_fill_keys($this->addresses, true);
        ksort($set);

        return $set;
    }
}
