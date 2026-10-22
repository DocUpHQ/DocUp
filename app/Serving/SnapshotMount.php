<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * One `domain_mounts` row, as the routing snapshot carries it (§8.10.1).
 *
 * §8.10.1 makes every hosting shape one of these rows — "default project
 * subdomain, custom domain, apex domain, additional serving domain, path-prefix
 * portal, collection grouping and preview host". The resolver therefore has one
 * matching rule rather than seven, which is the point: the eighth shape is a
 * row, not a code change.
 */
final class SnapshotMount
{
    /**
     * @param  string  $id  raw 16 bytes
     * @param  string  $pathPrefix  '' for a mount at the host root
     * @param  string  $mode  canonical, serve or redirect (§8.10.2)
     * @param  string  $mountExposure  the §12.3 lattice plus `inherit`
     * @param  list<string>|null  $versionScope  allowed version slugs, or null for all
     */
    public function __construct(
        public readonly string $id,
        public readonly string $pathPrefix,
        public readonly string $mode,
        public readonly string $mountExposure,
        public readonly bool $isIndexable,
        public readonly SnapshotProject $project,
        public readonly ?string $versioningSchemeOverride = null,
        public readonly ?array $versionScope = null,
    ) {}

    /**
     * The scheme §7.3's version step applies here.
     *
     * The mount's override wins over the project's own, which is what lets one
     * project serve `/{version}/` on its own domain and `/{lang}/{version}/` on
     * another (§10.5).
     */
    public function versioningScheme(): string
    {
        return $this->versioningSchemeOverride ?? $this->project->versioningScheme;
    }

    /**
     * Whether this mount exposes a version slug.
     *
     * §10.5's `version_scope` is an allowlist; null means every version the
     * project has. A mount that exposed a version outside its scope would let a
     * portal domain serve documentation the portal was configured not to show.
     */
    public function exposes(string $versionSlug): bool
    {
        return $this->versionScope === null || in_array($versionSlug, $this->versionScope, true);
    }
}
