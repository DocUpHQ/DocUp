<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * One project, as the routing snapshot carries it.
 *
 * Holds its versions, because §7.3's version step has to resolve without a
 * query: §8.9.1 requires the resolver to take "a pre-loaded routing snapshot,
 * with no database queries". A project with a thousand versions makes a large
 * snapshot, which is a real cost and the right one to pay — the alternative is
 * a query on the hottest path in the product, and §9.2's budgets do not have
 * room for one.
 */
final class SnapshotProject
{
    /**
     * @param  string  $id  raw 16 bytes
     * @param  list<SnapshotVersion>  $versions
     * @param  int  $routingEpoch  §8.9.10; part of the resolution cache key
     */
    public function __construct(
        public readonly string $id,
        public readonly string $slug,
        public readonly ?string $urlPrefix,
        public readonly string $versioningScheme,
        public readonly int $routingEpoch,
        public readonly string $visibility,
        public readonly string $chromeMode,
        public readonly ?string $defaultVersionId,
        public readonly array $versions = [],
    ) {}

    /** The version with this language and slug, whether servable or not. */
    public function version(string $language, string $slug): ?SnapshotVersion
    {
        foreach ($this->versions as $version) {
            if ($version->language === $language && $version->slug === $slug) {
                return $version;
            }
        }

        return null;
    }

    /**
     * Whether this project has any version in a language.
     *
     * Used to tell `language.not_found` from `version.not_found`, which matters
     * for §8.11.5's 404 chain: "a missing page in a non-default language MUST
     * return 404 plus a notification banner" (§8.6.13), and a banner cannot say
     * which of the two went wrong unless the resolver distinguishes them.
     */
    public function hasLanguage(string $language): bool
    {
        foreach ($this->versions as $version) {
            if ($version->language === $language) {
                return true;
            }
        }

        return false;
    }

    /**
     * The version §8.9.7's empty-path redirect goes to.
     *
     * 🛑 From the stored pointer, never derived. §8.6.14: the default version
     * "MUST be held as an explicit stored pointer on the project, not as a
     * derived value". A fallback to "the first servable version" would make the
     * redirect target change silently when a branch was created — and a
     * redirect that moves on its own is how an external link rots.
     *
     * Returns null when the pointer is unset or points at something unservable,
     * which §8.9.7 answers with a 404 rather than a guess.
     */
    public function defaultVersion(): ?SnapshotVersion
    {
        if ($this->defaultVersionId === null) {
            return null;
        }

        foreach ($this->versions as $version) {
            if ($version->id === $this->defaultVersionId) {
                return $version->isServable() ? $version : null;
            }
        }

        return null;
    }
}
