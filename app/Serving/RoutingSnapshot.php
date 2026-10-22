<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * Everything the resolver may know, for one hostname (§8.9.1).
 *
 * §8.9.1: "Hostname and path resolution MUST be performed by **one pure
 * resolver** taking a pre-loaded routing snapshot, with no database queries and
 * no framework dependencies."
 *
 * 🛑 "Pre-loaded" is the whole contract. The resolver cannot reach for anything
 * it was not given, so whatever a request can influence is visible in one place
 * — and §8.9.4's requirement that "no request header MUST act as a project,
 * version or tenant selector, in any environment" becomes checkable by reading
 * this constructor rather than by auditing a call graph.
 *
 * One snapshot is one host. The alternative — every host in one structure —
 * would make the snapshot grow with the installation and would put the §8.9.3
 * host-order decision inside the resolver, where it cannot be cached per host.
 * {@see HostMatcher} decides which host to load; this is what gets loaded.
 */
final class RoutingSnapshot
{
    /**
     * @param  string  $host  normalised, as {@see HostMatcher::normalise()} returns it
     * @param  bool  $servable  §8.10.6: an unverified or suspended host serves nothing
     * @param  list<SnapshotMount>  $mounts
     */
    public function __construct(
        public readonly string $host,
        public readonly HostKind $kind,
        public readonly bool $servable,
        public readonly array $mounts,
    ) {}

    /**
     * The mount covering a path: longest `path_prefix` first, on a segment
     * boundary (§7.3).
     *
     * 🛑 "On a segment boundary" is not decoration. A mount at `api` must not
     * match a request for `apiary/guide.html`, and a plain `str_starts_with`
     * would — which is how one project's portal mount quietly swallows another
     * project's URLs on a shared domain.
     *
     * @param  string  $path  the request path, leading slash included
     */
    public function mountFor(string $path): ?SnapshotMount
    {
        $relative = ltrim($path, '/');
        $best = null;
        $bestLength = -1;

        foreach ($this->mounts as $mount) {
            $prefix = $mount->pathPrefix;
            $length = strlen($prefix);

            if ($length <= $bestLength) {
                continue;
            }

            if ($prefix === '') {
                // The root mount matches everything, and is the shortest
                // possible match — so it only wins when nothing longer does.
                $best = $mount;
                $bestLength = 0;

                continue;
            }

            if (! str_starts_with($relative, $prefix)) {
                continue;
            }

            // The match must end at the end of the path or immediately before a
            // separator.
            $next = $relative[$length] ?? '/';

            if ($next !== '/') {
                continue;
            }

            $best = $mount;
            $bestLength = $length;
        }

        return $best;
    }

    /** An unroutable host: known to the matcher, unknown to the installation. */
    public static function empty(string $host, HostKind $kind): self
    {
        return new self($host, $kind, servable: false, mounts: []);
    }
}
