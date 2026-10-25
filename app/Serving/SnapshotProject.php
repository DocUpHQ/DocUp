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
     * @param  array<string, string>  $formerSlugs  §8.6.6's 301 table, keyed
     *                                              `<language>:<old slug>` =>
     *                                              the version's id
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
        public readonly array $formerSlugs = [],
    ) {}

    /**
     * §8.6.6: "a renamed slug MUST leave a working 301 behind it."
     *
     * 🛑 In the SNAPSHOT rather than queried per request. §8.9.1 requires
     * the resolver to run "with no database queries", and a rename is rare
     * while a 404 is not — looking the history up only on a miss would put
     * a query behind every probe for a path that does not exist, which is
     * precisely what §8.11.8's rate limiter exists because attackers send
     * in volume.
     *
     * Returns the version the old slug now names, or null.
     */
    public function versionByFormerSlug(string $language, string $slug): ?SnapshotVersion
    {
        $id = $this->formerSlugs[$language.':'.$slug] ?? null;

        if ($id === null) {
            return null;
        }

        foreach ($this->versions as $version) {
            if ($version->id === $id) {
                /*
                 * 🛑 Only if it would actually serve. A 301 to a URL that
                 * 404s is worse than the 404: a crawler follows it, caches
                 * the redirect, and returns to the same dead end tomorrow.
                 */
                return $version->isServable() ? $version : null;
            }
        }

        return null;
    }

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
     * 🛑 §8.6.12's translation group: the same documentation, other languages.
     *
     * > "Language MUST be a property of a project version with a
     * > `translation_group_id`, **not** a sibling project."
     *
     * 🛑 **The group, never the slug.** `/en/v2/` and `/ja/v2/` are two rows
     * sharing a slug by design (§10.4), and matching on the slug would be
     * close enough right up to the moment a translator slugs the Japanese
     * version `v2-ja` — which is what a translator does when the slug is
     * user-visible. It would also be wrong in the other direction: two
     * versions of one project can share a slug across languages without
     * being translations of each other.
     *
     * Includes the version itself, because hreflang annotations are
     * self-referential (§8.11.6) and a language switcher showing every
     * language but the current one has to filter anyway. Unservable siblings
     * are excluded: an alternate pointing at a version with nothing published
     * is an annotated 404.
     *
     * @return list<SnapshotVersion>
     */
    public function translationsOf(SnapshotVersion $version): array
    {
        if ($version->translationGroupId === null) {
            return $version->isServable() ? [$version] : [];
        }

        $group = [];

        foreach ($this->versions as $candidate) {
            if ($candidate->translationGroupId === $version->translationGroupId && $candidate->isServable()) {
                $group[] = $candidate;
            }
        }

        usort($group, static fn (SnapshotVersion $a, SnapshotVersion $b): int => strcmp($a->language, $b->language));

        return $group;
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
