<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * Where a project's canonical mount lives (§8.10.3, §8.11.9).
 *
 * §8.10.3 puts exactly one canonical mount per project behind a unique index,
 * and §8.11.9 makes it the target of every `rel=canonical`: "For N domains
 * serving identical content, canonical MUST always point at the project's
 * canonical mount." §8.11.6's `hreflang` alternates are built on the same
 * mount, for the same reason — annotating a page on a host the response has
 * just told a crawler to ignore is worse than not annotating it.
 *
 * `$origin` is `scheme://host` with no trailing slash; `$pathPrefix` is the
 * mount's own, `''` at the host root.
 */
final readonly class CanonicalLocation
{
    public function __construct(
        public string $origin,
        public string $pathPrefix,
    ) {}

    /**
     * A snapshot mount standing in for the canonical one, for URL building.
     *
     * 🛑 So that {@see VersionUrl} is the only thing that joins §7.3's
     * segments, here as well as on the serving path. The alternative — a
     * second `implode` over prefix, language and slug in whatever class
     * happens to need a URL — is how the canonical path and the served path
     * come to differ by a trailing slash that nobody notices until a crawler
     * reports duplicate content.
     */
    public function mountFor(SnapshotProject $project): SnapshotMount
    {
        return new SnapshotMount(
            id: '',
            pathPrefix: $this->pathPrefix,
            mode: 'canonical',
            mountExposure: 'inherit',
            isIndexable: true,
            project: $project,
        );
    }
}
