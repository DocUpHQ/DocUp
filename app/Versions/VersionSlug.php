<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Versions;

/**
 * §8.6.6's ref-name-to-slug function, stated once.
 *
 * > "The system MUST derive a version slug from a ref name by one stated,
 * > deterministic function — lowercase, with spaces, `/` and every character
 * > outside the permitted set replaced by `-` — over a documented permitted
 * > character set, with a documented deterministic suffix on collision, a
 * > documented maximum length, and a documented rule for a name that reduces
 * > to the empty string. Slugs MUST be editable, 🛑 MUST NOT collide with any
 * > reserved segment (`_`, a language code, a collection alias)."
 *
 * 🛑 **A slug is a URL segment, which is why every rule here is about the
 * URL rather than about tidiness.** `release/2.0` becoming `release-2.0`
 * matters because a `/` would make one version look like two path segments
 * to §7.3's grammar and to every redirect rule written against it; the
 * reserved-segment refusal matters because `_` is §8.9's own prefix and a
 * version slugged `en` under `lang_and_version` is a URL nobody can resolve.
 *
 * 🛑 **Deterministic, including on collision.** The same ref name must
 * produce the same slug on a second sync, or a re-discovered branch gets a
 * second version row and the first one's URLs go stale. The collision suffix
 * is therefore derived from the ref name rather than from a counter — a
 * counter depends on insertion order, which depends on what the provider
 * listed first.
 */
final class VersionSlug
{
    /**
     * §8.6.6's permitted set: lowercase letters, digits, `.`, `_` and `-`.
     *
     * A dot is in because `v1.2.3` is the overwhelmingly common tag shape and
     * slugging it to `v1-2-3` would make every URL unrecognisable to the
     * people who wrote the tag. An underscore is in because it is already
     * legal in a ref name and harmless in a path segment.
     */
    private const PERMITTED = '/[^a-z0-9._-]+/';

    /**
     * 🛑 80 characters, matching `project_versions.slug`'s column.
     *
     * Stated here as well as in the schema because a truncation that happens
     * in MySQL rather than here is a truncation that happens *after* the
     * uniqueness check — two refs differing only past character 80 would both
     * pass and then collide on insert.
     */
    public const MAX_LENGTH = 80;

    /**
     * What a ref that reduces to nothing becomes.
     *
     * §8.6.6 requires "a documented rule for a name that reduces to the empty
     * string". A ref named `...` or `///` is legal in git and slugs to
     * nothing; it gets this plus the collision suffix, so it is addressable
     * and distinct rather than silently dropped.
     */
    public const EMPTY_FALLBACK = 'version';

    /**
     * 🛑 Segments a slug may never be (§8.6.6).
     *
     * `_` is §8.9's reserved prefix — `/_/provenance`, `/_/addons`,
     * `/_/health` all live there. `.well-known` is the resolver's other
     * reserved segment. The two-letter language codes are refused because
     * `lang_and_version` puts a language in the same position a version
     * occupies under `multi_version`, and a project that switched scheme
     * would find one of its versions unreachable.
     *
     * @var list<string>
     */
    public const RESERVED = ['_', '.well-known', 'page', 'api', 'static', 'media'];

    /**
     * Derive a slug from a ref name.
     *
     * @param  list<string>  $taken  slugs already used in this project and language
     */
    public static function fromRef(string $ref, array $taken = []): string
    {
        $base = self::normalise($ref);

        if (! in_array($base, $taken, true) && ! self::isReserved($base)) {
            return $base;
        }

        return self::withSuffix($base, $ref, $taken);
    }

    /**
     * The normalisation half, without collision handling.
     *
     * Separate so that an operator editing a slug by hand is held to the same
     * character set as the automatic path, and so the function can be tested
     * without a database.
     */
    public static function normalise(string $ref): string
    {
        // `refs/heads/` and `refs/tags/` are the advertisement's framing, not
        // part of the name anybody typed.
        $name = preg_replace('#^refs/(heads|tags)/#', '', trim($ref)) ?? $ref;

        $slug = preg_replace(self::PERMITTED, '-', mb_strtolower($name, 'UTF-8')) ?? '';

        // Runs collapse and the edges are trimmed, so `release//2.0` and
        // `release/2.0` produce the same slug rather than two that differ by
        // an invisible hyphen.
        $slug = trim((string) preg_replace('/-{2,}/', '-', $slug), '-.');

        if ($slug === '') {
            return self::EMPTY_FALLBACK;
        }

        return mb_substr($slug, 0, self::MAX_LENGTH, 'UTF-8');
    }

    public static function isReserved(string $slug): bool
    {
        if (in_array($slug, self::RESERVED, true)) {
            return true;
        }

        /*
         * 🛑 Any two- or three-letter sequence that could be a language code,
         * not a list of the ones we currently ship. §8.6.12 makes language a
         * version property and §8.6.9's `lang_and_version` puts it in a path
         * segment; a version slugged `fr` is unreachable the day somebody
         * adds a French translation, which is long after the slug was
         * chosen. Refusing the shape rather than the membership means that
         * day never comes.
         */
        return preg_match('/^[a-z]{2,3}(-[a-z0-9]{2,8})?$/', $slug) === 1;
    }

    /**
     * §8.6.6's "documented deterministic suffix on collision".
     *
     * 🛑 Derived from the full ref name, never from a counter. The same ref
     * must slug the same way on every sync — a counter would depend on which
     * refs the provider happened to list first, so a re-ordered advertisement
     * would rename a version and strand its URLs.
     *
     * @param  list<string>  $taken
     */
    private static function withSuffix(string $base, string $ref, array $taken): string
    {
        $digest = substr(hash('sha256', $ref), 0, 6);
        $room = self::MAX_LENGTH - strlen($digest) - 1;
        $candidate = mb_substr($base, 0, max(1, $room), 'UTF-8').'-'.$digest;

        if (! in_array($candidate, $taken, true)) {
            return $candidate;
        }

        /*
         * Two different refs whose names hash to the same six characters and
         * whose slugs already collide. Astronomically unlikely and still
         * handled, because the alternative is an insert that violates
         * `project_versions_slug_unique` and surfaces as a 500 during a ref
         * sync nobody is watching.
         */
        for ($attempt = 2; $attempt < 100; $attempt++) {
            $wider = substr(hash('sha256', $ref.':'.$attempt), 0, 6);
            $candidate = mb_substr($base, 0, max(1, $room), 'UTF-8').'-'.$wider;

            if (! in_array($candidate, $taken, true)) {
                return $candidate;
            }
        }

        throw new \RuntimeException('could not derive a unique version slug for '.$ref);
    }
}
