<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Egress;

/**
 * What an IP address is, for the purposes of §8.3.4 and §8.3.9.
 *
 * 🛑 One enum case per **control**, not one per CIDR. §8.3.4 names RFC1918,
 * loopback, link-local, ULA and `169.254.169.254` separately, and Phase 05's
 * exit criteria require the refusals to be told apart. An operator who has
 * pointed DocUp at `10.0.0.5` by mistake and an attacker reaching for the cloud
 * metadata endpoint produce very different answers from the same code path, and
 * a single `denied` would make them indistinguishable in a log.
 *
 * `Metadata` is deliberately checked **before** `LinkLocal` even though
 * `169.254.169.254` is inside `169.254.0.0/16`: the narrower control is the one
 * worth naming when it fires.
 */
enum AddressClass: string
{
    /** Routable on the public internet. The only class egress may reach. */
    case Public = 'public';

    /** `127.0.0.0/8`, `::1`. */
    case Loopback = 'loopback';

    /** RFC1918, plus CGNAT `100.64.0.0/10` and the benchmarking range. */
    case Private = 'private';

    /** `169.254.0.0/16`, `fe80::/10` — minus the metadata address below. */
    case LinkLocal = 'link_local';

    /**
     * `169.254.169.254` and `fd00:ec2::254`.
     *
     * Named on its own because it is the one address in this file that is a
     * credential-theft primitive rather than a misconfiguration: on most cloud
     * providers an unauthenticated GET returns the instance's role credentials.
     */
    case Metadata = 'metadata';

    /** `fc00::/7` — IPv6 unique local addresses. */
    case UniqueLocal = 'unique_local';

    /** `0.0.0.0`, `::` — routed to the local host by most stacks. */
    case Unspecified = 'unspecified';

    /** Multicast, broadcast, `240.0.0.0/4`, and everything else not for us. */
    case Reserved = 'reserved';

    /** True when egress to this address is permitted. */
    public function isRoutable(): bool
    {
        return $this === self::Public;
    }

    /** The §8.3.9 rejection this class produces when egress is attempted. */
    public function rejection(): EgressRejection
    {
        return match ($this) {
            self::Public => throw new \LogicException('a public address is not a rejection'),
            self::Loopback => EgressRejection::LoopbackAddressDenied,
            self::Private => EgressRejection::PrivateAddressDenied,
            self::LinkLocal => EgressRejection::LinkLocalAddressDenied,
            self::Metadata => EgressRejection::MetadataAddressDenied,
            self::UniqueLocal => EgressRejection::UniqueLocalAddressDenied,
            self::Unspecified => EgressRejection::UnspecifiedAddressDenied,
            self::Reserved => EgressRejection::ReservedAddressDenied,
        };
    }
}
