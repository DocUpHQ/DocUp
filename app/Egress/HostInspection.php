<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Egress;

/**
 * The verdict on one hostname: refused, or pinned to one address.
 *
 * 🛑 `pinnedAddress` is the whole point of "resolve-then-pin" (§8.3.4, §8.3.9).
 * The caller connects to **this literal address** and sends the original name
 * in `Host` and SNI. Handing the hostname to the transport and letting it
 * resolve again would reintroduce the window the inspection just closed: the
 * check and the connection would be two different lookups, and the attacker
 * only has to win the second one.
 */
final readonly class HostInspection
{
    /**
     * @param  list<string>  $addresses  every address the name answered with
     * @param  string|null  $offendingAddress  the address that caused a refusal
     */
    private function __construct(
        public ?EgressRejection $rejection,
        public ?string $pinnedAddress,
        public array $addresses,
        public ?int $ttl,
        public ?string $offendingAddress,
        public ?AddressClass $offendingClass,
    ) {}

    /** @param  list<string>  $addresses */
    public static function pinned(string $pinnedAddress, array $addresses, ?int $ttl): self
    {
        return new self(null, $pinnedAddress, $addresses, $ttl, null, null);
    }

    /** @param  list<string>  $addresses */
    public static function refused(
        EgressRejection $rejection,
        array $addresses = [],
        ?int $ttl = null,
        ?string $offendingAddress = null,
        ?AddressClass $offendingClass = null,
    ): self {
        return new self($rejection, null, $addresses, $ttl, $offendingAddress, $offendingClass);
    }

    public function isRefused(): bool
    {
        return $this->rejection !== null;
    }

    /**
     * Context for the audit record and the operator-facing error.
     *
     * 🛑 Addresses, classes and TTLs only. No URL, no header, no credential —
     * this structure is logged, and Phase 05's exit criteria include "no token
     * appears in any log, at any log level". Keeping the shape narrow here is
     * cheaper than scrubbing it downstream.
     *
     * @return array<string, mixed>
     */
    public function context(): array
    {
        return array_filter([
            'rejection' => $this->rejection?->value,
            'addresses' => $this->addresses,
            'pinned' => $this->pinnedAddress,
            'ttl' => $this->ttl,
            'offending_address' => $this->offendingAddress,
            'offending_class' => $this->offendingClass?->value,
        ], static fn (mixed $value): bool => $value !== null && $value !== []);
    }
}
