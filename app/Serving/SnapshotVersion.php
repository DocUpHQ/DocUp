<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * One version, as the routing snapshot carries it.
 *
 * 🛑 §8.6.2's four axes are all present and none is derived from another:
 * "Version visibility MUST be modelled as **four independent axes** —
 * `active`, `listed`, `published` and `visibility` — which MUST NOT be
 * collapsed or derived from one another, with a test proving their
 * independence." The resolver reads `active` and `published`; `listed` is the
 * flyout's and `visibility` is §12.3's. Collapsing them here would be the
 * collapse the requirement forbids, just in a different file.
 *
 * `hidden` is not `private`: a version that is `active` and `published` but not
 * `listed` serves by direct URL and is absent from the flyout, the sitemap and
 * search. So the resolver must not consult `listed` at all, or an unlisted
 * version would 404 on a URL somebody was given.
 */
final class SnapshotVersion
{
    /**
     * @param  string  $id  raw 16 bytes
     * @param  string|null  $publishedManifestId  raw 16 bytes, null when nothing is published
     * @param  string|null  $previousManifestId  raw 16 bytes; §8.8.6's soft landing
     * @param  int|null  $softLandingExpiresAt  unix seconds, or null
     * @param  string|null  $translationGroupId  raw 16 bytes; §8.6.12's group, null when ungrouped
     */
    public function __construct(
        public readonly string $id,
        public readonly string $slug,
        public readonly string $language,
        public readonly bool $active,
        public readonly bool $listed,
        public readonly bool $published,
        public readonly string $visibility,
        public readonly ?string $publishedManifestId = null,
        public readonly ?string $previousManifestId = null,
        public readonly ?int $softLandingExpiresAt = null,
        public readonly ?string $translationGroupId = null,
    ) {}

    /**
     * Whether this version may answer a request at all.
     *
     * 🛑 `active` and `published`, and deliberately **not** `listed`. An
     * unlisted version is reachable by direct URL by design (§8.6.2), so
     * including `listed` here would 404 every link anyone had been given to a
     * hidden version — which is the behaviour §8.6.2 distinguishes `hidden`
     * from `private` precisely to avoid.
     */
    public function isServable(): bool
    {
        return $this->active && $this->published && $this->publishedManifestId !== null;
    }

    /**
     * The manifest still resolvable for an asset of the previous build
     * (§8.8.6).
     *
     * Returns null once the window has closed. The window is what stops a
     * publish breaking every page currently open: a document delivered a second
     * before the flip holds relative asset URLs that resolve against the old
     * build, and without this the next request for one is a 404 in a reader's
     * browser.
     */
    public function softLandingManifestId(int $now): ?string
    {
        if ($this->previousManifestId === null || $this->softLandingExpiresAt === null) {
            return null;
        }

        return $this->softLandingExpiresAt > $now ? $this->previousManifestId : null;
    }
}
