<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Source;

use App\Egress\AddressGuard;
use App\Egress\EgressOptions;

/**
 * §8.3.4, in full, at attach time.
 *
 * > "🛑 The system MUST reject repository URLs that are not `https://` or
 * > `ssh://`; MUST set git `protocol.allow=never` with explicit per-protocol
 * > allowances; MUST resolve-then-pin DNS and reject RFC1918, loopback,
 * > link-local, ULA and `169.254.169.254`; and MUST disable redirects.
 * > `ext::sh -c id` and `file:///etc` are remote code execution and local file
 * > disclosure respectively, and both are reachable from a repository URL
 * > field."
 *
 * Three of those four clauses live here: the scheme rule and the two named
 * attacks in {@see RepositoryUrl::parse()}, and the address rules below. The
 * git configuration clause is {@see GitSafety}, and redirects are refused by
 * the §8.3.9 egress client during the reachability probe.
 *
 * 🛑 **The order is the control.** Shape first, because a string that is not a
 * URL must never reach a resolver — `ext::sh -c id` has no host to resolve and
 * a policy that tried would either crash or, worse, pass. Addresses second,
 * with every answer classified, not just the one we would use.
 */
final readonly class GitUrlPolicy
{
    public function __construct(private AddressGuard $guard) {}

    /**
     * @param  bool  $enforceAddressPolicy  false ONLY in the integration tests
     *                                      that need a loopback server; see
     *                                      {@see EgressOptions}
     *
     * @throws SourceRefused
     */
    public function inspect(string $input, bool $enforceAddressPolicy = true): InspectedRepositoryUrl
    {
        $url = RepositoryUrl::parse($input);

        $inspection = $this->guard->inspect($url->host, $enforceAddressPolicy);

        if ($inspection->rejection !== null) {
            throw new SourceRefused(
                SourceRejection::fromEgress($inspection->rejection),
                $url->host,
                $inspection->context(),
            );
        }

        return new InspectedRepositoryUrl(
            url: $url,
            pinnedAddress: (string) $inspection->pinnedAddress,
            addresses: $inspection->addresses,
            provider: Provider::forHost($url->host),
        );
    }

    /**
     * The rejection a URL would produce, or null when it is acceptable.
     *
     * For the dashboard's inline validation, where an exception is the wrong
     * shape. The implementation is {@see inspect()}, not a second copy of the
     * rules — a validator that disagrees with the enforcer is worse than no
     * validator, because it teaches operators that the field lies.
     */
    public function rejectionFor(string $input, bool $enforceAddressPolicy = true): ?SourceRejection
    {
        try {
            $this->inspect($input, $enforceAddressPolicy);

            return null;
        } catch (SourceRefused $refused) {
            return $refused->rejection;
        }
    }
}
