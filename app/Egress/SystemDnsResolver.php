<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Egress;

/**
 * The production resolver: the host's own stub resolver, through PHP.
 *
 * 🛑 Both families are queried, and the answer is the **union**. Asking only
 * for A records is a documented SSRF bypass: a name with no A record and an
 * AAAA record pointing at `::1` resolves to nothing in an IPv4-only check, the
 * guard waves it through as unresolvable-but-harmless or falls back to letting
 * the transport resolve it, and the transport then connects over IPv6 to
 * loopback. The guard must see every address the connection could use.
 */
final class SystemDnsResolver implements DnsResolver
{
    public function resolve(string $host): ResolvedHost
    {
        $addresses = [];
        $ttls = [];

        foreach ([DNS_A, DNS_AAAA] as $type) {
            $records = @dns_get_record($host, $type);

            if ($records === false) {
                continue;
            }

            foreach ($records as $record) {
                $address = $record['ip'] ?? $record['ipv6'] ?? null;

                if (is_string($address) && $address !== '') {
                    $addresses[] = $address;

                    if (isset($record['ttl']) && is_int($record['ttl'])) {
                        $ttls[] = $record['ttl'];
                    }
                }
            }
        }

        /*
         * `dns_get_record` talks to the configured nameservers directly and
         * therefore misses `/etc/hosts`, container DNS aliases and anything
         * else the stub resolver would honour. An address the application
         * would actually connect to but the guard never saw is the failure
         * this fallback exists to prevent, so it runs whenever the direct
         * query came back empty — including when it came back empty because
         * the query failed.
         */
        if ($addresses === []) {
            $fallback = @gethostbynamel($host);

            if (is_array($fallback)) {
                $addresses = array_values(array_filter($fallback, 'is_string'));
            }
        }

        return new ResolvedHost(
            array_values(array_unique($addresses)),
            $ttls === [] ? null : min($ttls),
        );
    }
}
