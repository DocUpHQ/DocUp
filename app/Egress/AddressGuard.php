<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Egress;

/**
 * Resolve-then-pin with a rebind check (§8.3.4, §8.3.9).
 *
 * 🛑 One implementation, two surfaces. The §8.3.9 egress client uses it before
 * every outbound request; `App\Source\GitUrlPolicy` uses it to refuse a
 * repository URL at attach time, long before anything is fetched. Those are
 * different vocabularies — a repository URL rejection is reported with a
 * `git_url.*` identifier an author can act on — but they must not be different
 * *implementations*. Two copies of an SSRF deny list diverge on the first CVE
 * that only one of them hears about.
 *
 * This class makes no outbound request of its own, which is why it may live
 * beside the egress client rather than inside it, and why
 * `ArchitectureTest::test_only_the_egress_namespace_makes_outbound_requests`
 * does not have to carve an exception for its callers.
 */
final readonly class AddressGuard
{
    public function __construct(
        private DnsResolver $resolver,
        private IpAddressClassifier $classifier,
    ) {}

    /**
     * Resolve a host, refuse every address class §8.3.4 denies, and pin.
     *
     * @param  string  $host  a hostname, an IPv4 literal, or an IPv6 literal
     *                        with or without brackets
     * @param  bool  $enforceAddressPolicy  false ONLY in the integration tests
     *                                      that exercise the redirect and byte-cap controls
     *                                      against a real loopback server. Nothing in `app/`
     *                                      passes false, and an architecture test says so.
     */
    public function inspect(string $host, bool $enforceAddressPolicy = true): HostInspection
    {
        $host = $this->unbracket($host);

        /*
         * A literal address has no name to rebind, so there is nothing to
         * re-resolve and nothing to compare. Classify it and pin it, or refuse.
         */
        if (@inet_pton($host) !== false) {
            $class = $this->classifier->classify($host);

            if ($enforceAddressPolicy && ! $class->isRoutable()) {
                return HostInspection::refused($class->rejection(), [$host], null, $host, $class);
            }

            return HostInspection::pinned($host, [$host], null);
        }

        $first = $this->resolver->resolve($host);

        if ($first->isEmpty()) {
            return HostInspection::refused(EgressRejection::HostNotResolvable);
        }

        if ($enforceAddressPolicy) {
            $offender = $this->firstOffender($first);

            if ($offender !== null) {
                [$address, $class] = $offender;

                return HostInspection::refused(
                    $class->rejection(),
                    $first->addresses,
                    $first->ttl,
                    $address,
                    $class,
                );
            }

            $rebind = $this->detectRebind($host, $first);

            if ($rebind !== null) {
                return $rebind;
            }
        }

        return HostInspection::pinned($first->addresses[0], $first->addresses, $first->ttl);
    }

    /**
     * The rebind control: ask again, and refuse if the second answer brings an
     * address the first one would have been refused for.
     *
     * 🛑 The condition is deliberately **not** "the two answers differ".
     * Round-robin and geo-steered DNS legitimately return different subsets of
     * a public RRset from one query to the next, and a guard that refused on
     * any difference would refuse `api.github.com` intermittently — the kind
     * of failure that gets a security control switched off rather than fixed.
     * What is never legitimate is a name that answers publicly once and
     * privately the next time, milliseconds later. That is the attack, and it
     * is the only thing refused here.
     *
     * The request is pinned to the first answer regardless, so this check is
     * defence in depth rather than the defence: it turns a name that *tried*
     * the attack into a refusal with its own identifier, instead of a request
     * that quietly succeeded against the address we had already validated.
     */
    private function detectRebind(string $host, ResolvedHost $first): ?HostInspection
    {
        $second = $this->resolver->resolve($host);

        if ($second->isEmpty() || $second->asSet() === $first->asSet()) {
            return null;
        }

        $offender = $this->firstOffender($second);

        if ($offender === null) {
            return null;
        }

        [$address, $class] = $offender;

        return HostInspection::refused(
            EgressRejection::DnsRebindDetected,
            array_values(array_unique([...$first->addresses, ...$second->addresses])),
            $second->ttl ?? $first->ttl,
            $address,
            $class,
        );
    }

    /**
     * The first address in the answer that §8.3.4 denies, with its class.
     *
     * 🛑 **Every** address is checked, not just the one we would connect to. A
     * name answering `[93.184.216.34, 127.0.0.1]` is refused outright: we
     * cannot know which address the connection would have used if the pin ever
     * failed open, and a name that publishes loopback alongside a public
     * address is not a name we have any business fetching from.
     *
     * @return array{0: string, 1: AddressClass}|null
     */
    private function firstOffender(ResolvedHost $resolved): ?array
    {
        foreach ($resolved->addresses as $address) {
            $class = $this->classifier->classify($address);

            if (! $class->isRoutable()) {
                return [$address, $class];
            }
        }

        return null;
    }

    /** `[::1]` as it appears in a URL authority, to `::1` as `inet_pton` wants it. */
    private function unbracket(string $host): string
    {
        if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
            return substr($host, 1, -1);
        }

        return $host;
    }
}
