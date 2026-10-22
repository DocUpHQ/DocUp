<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * One way a hostname might resolve, and what to look up for it.
 *
 * Produced by {@see HostMatcher} and consumed by whatever loads the routing
 * snapshot. The separation exists so that §8.9.3's ordering is decided purely —
 * from the hostname and the configured apexes, with no query — and the loader
 * then performs at most one lookup per candidate in that order.
 *
 * 🛑 A candidate is a *question*, never an answer. §8.9.3 forbids falling
 * through to a default project, so a candidate that finds nothing contributes
 * nothing: the sequence ends in a hard 404, not in a guess.
 */
final class HostCandidate
{
    /**
     * @param  string  $lookupHost  the hostname to match a `domains` row against
     * @param  string|null  $projectSlug  for a default subdomain and a preview
     *                                    host, the label that names the project
     * @param  string|null  $versionSlug  for a preview host, the version after
     *                                    the last `--`
     */
    public function __construct(
        public readonly HostKind $kind,
        public readonly string $lookupHost,
        public readonly ?string $projectSlug = null,
        public readonly ?string $versionSlug = null,
    ) {}
}
