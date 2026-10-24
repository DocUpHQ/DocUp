<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Sandbox;

use App\Builds\BuildConfig;

/**
 * §8.5.9's egress allowlist, as the application reads it.
 *
 * > "Egress MUST default to an allowlisted CONNECT proxy (PyPI, npm,
 * > crates.io, `proxy.golang.org`, rubygems.org, configured git hosts,
 * > operator additions)"
 *
 * 🛑 **This class does not hold the list; it reads the file the proxy
 * enforces.** `deploy/egress-allowlist.conf` has two readers — squid, which
 * renders its ACLs from it at start-up, and this, which answers
 * `docup:doctor`, the §8.5.12 self-test and the question "which host did the
 * proxy refuse, and is it on the list?". A PHP copy of the same names would
 * drift from the list actually enforced, and the drift would be invisible
 * until somebody was told a host was allowed by a proxy refusing it
 * (ADR 0011).
 *
 * The parsing rules are duplicated from `deploy/proxy-entrypoint.sh` on
 * purpose, and `EgressAllowlistTest` asserts that the two agree on a
 * wildcard: a validator that is more permissive than the enforcer is how a
 * rejected entry comes to look accepted.
 */
final readonly class EgressAllowlist
{
    /** @param list<string> $hosts */
    private function __construct(public array $hosts, public string $path) {}

    /**
     * Read the configured allowlist.
     *
     * 🛑 A missing or unreadable file yields an **empty** list, never a
     * default one. The proxy refuses to start on an unreadable allowlist
     * for the same reason: an invented default here would tell an operator
     * that PyPI was reachable from a build whose proxy had never started.
     */
    public static function load(): self
    {
        $path = BuildConfig::string('sandbox.allowlist_file', '');

        if ($path === '' || ! is_readable($path)) {
            return new self([], $path);
        }

        $contents = @file_get_contents($path);

        return new self(self::parse($contents === false ? '' : $contents), $path);
    }

    /** @param list<string> $hosts */
    public static function of(array $hosts): self
    {
        return new self($hosts, '(in memory)');
    }

    /**
     * 🛑 Exact hostnames only. A leading dot is squid's subdomain wildcard
     * and an entry of `.pythonhosted.org` would hand every build on the
     * installation any host anybody can register under that name. Dropped
     * here and refused outright by the proxy's own renderer — the proxy is
     * the one that gets to be loud, because it can refuse to start.
     *
     * @return list<string>
     */
    private static function parse(string $contents): array
    {
        $hosts = [];

        foreach (preg_split('/\R/', $contents) ?: [] as $line) {
            $host = trim(preg_replace('/#.*/', '', $line) ?? '');

            if ($host === '' || ! self::isExactHostname($host)) {
                continue;
            }

            $hosts[strtolower($host)] = true;
        }

        return array_keys($hosts);
    }

    /** A hostname with no wildcard, no scheme, no port and no path. */
    public static function isExactHostname(string $host): bool
    {
        return preg_match('/^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$/', $host) === 1
            && ! str_starts_with($host, '.')
            && strlen($host) <= 253;
    }

    /**
     * 🛑 Case-folded, exact. Never a suffix test: `permits('evilgithub.com')`
     * must be false with `github.com` on the list, and `str_ends_with` would
     * say otherwise. §8.3.6 made the same mistake available for repository
     * hosts and §9.1.6's `ascii_bin` note exists because host comparison is
     * byte-exact.
     */
    public function permits(string $host): bool
    {
        return in_array(strtolower(trim($host)), $this->hosts, true);
    }

    public function isEmpty(): bool
    {
        return $this->hosts === [];
    }
}
