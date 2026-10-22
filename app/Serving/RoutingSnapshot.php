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
     * The mount covering a path, and the path left inside it (§7.3).
     *
     * 🛑 The boundary rule lives in {@see SegmentPrefix} and nowhere else, so
     * matching and consuming cannot disagree. They used to: this method
     * returned only the mount and the resolver stripped the prefix again, which
     * left a defensive branch for a disagreement that could not happen — dead
     * code guarding two implementations of one rule.
     *
     * @param  string  $path  the request path, leading slash included
     */
    public function matchFor(string $path): ?DomainMountMatch
    {
        $relative = ltrim($path, '/');

        $prefixes = array_map(
            static fn (SnapshotMount $mount): string => $mount->pathPrefix,
            $this->mounts,
        );

        $match = SegmentPrefix::longest($prefixes, $relative);

        if ($match === null) {
            return null;
        }

        [$prefix, $remainder] = $match;

        foreach ($this->mounts as $mount) {
            if ($mount->pathPrefix === $prefix) {
                return new DomainMountMatch($mount, $remainder);
            }
        }

        // Unreachable: the prefix came from this list. Returning null rather
        // than asserting, because a 404 is the safe answer on the serving path
        // and a type error is not.
        return null;
    }

    /** An unroutable host: known to the matcher, unknown to the installation. */
    public static function empty(string $host, HostKind $kind): self
    {
        return new self($host, $kind, servable: false, mounts: []);
    }
}
