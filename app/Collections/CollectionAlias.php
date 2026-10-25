<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Collections;

use App\Versions\VersionSlug;

/**
 * 🛑 What a collection alias may be, stated once (§8.2.6, §8.21.2).
 *
 * An alias is a **path segment**, and §17.4 froze §7.3's grammar at the end
 * of Phase 04 — so every collision an alias could cause has to be refused by
 * name rather than resolved by a new rule. Phase 16's exit criterion names
 * three of them: "A collection alias colliding with a version slug, a
 * language code or `/_/` is rejected."
 *
 * 🛑 **Which refusals apply depends on where the alias stands**, and §8.2.6
 * makes that a column: under the default `projects` convention the alias is
 * one segment deeper than §7.3's language and version steps
 * (`/projects/<alias>/<lang>/<version>/`), and under `alias` it is in exactly
 * their position (`/<alias>/<lang>/<version>/`).
 *
 * So the language-code refusal is conditional, and it has to be. It is not a
 * matter of taste: `api` — the single most common Read the Docs subproject
 * name, whose URL §8.21.2 promises will keep resolving — is three lowercase
 * letters and therefore indistinguishable from an ISO 639-2 code. Under
 * `/projects/api/` nothing is ambiguous and refusing it would break the
 * compatibility promise to protect a position the alias does not occupy;
 * under `/api/` it is ambiguous with a language segment and **is** refused.
 *
 * 🛑 Which means the convention cannot be changed freely:
 * {@see Collections::changeConvention()} re-validates every alias before
 * switching to `alias`, because the switch is where a safe alias becomes an
 * ambiguous one and nobody is looking at aliases at that moment.
 *
 * 🛑 **The language-code test itself is `VersionSlug::isLanguageCodeShaped()`
 * and not a copy of it.** One function, so an alias named `ja` cannot become
 * legal six months after a version slugged `ja` was refused.
 *
 * 🛑 **The rest of `VersionSlug::RESERVED` is deliberately NOT applied.**
 * That list also holds `static` and `media`, which are version-slug
 * precautions rather than §7.3 reservations, and the documentation origin
 * serves neither: §8.1.4 puts the REST API and the asset host on other
 * registrable domains.
 */
final class CollectionAlias
{
    /**
     * 🛑 64 characters, matching `collection_projects.alias`.
     *
     * Stated here as well as in the schema for the reason
     * {@see VersionSlug::MAX_LENGTH} is: a truncation that happens in MySQL
     * happens *after* the uniqueness check, so two aliases differing only
     * past character 64 would both pass and then collide on insert.
     */
    public const MAX_LENGTH = 64;

    /**
     * Lowercase alphanumerics, `-` and `_`, never at an edge.
     *
     * Narrower than §8.6.6's version-slug set, which also permits `.`. A dot
     * is in there because `v1.2.3` is the dominant tag shape and slugging it
     * would make the URL unrecognisable; an alias is chosen by an operator
     * rather than derived from a ref, so nothing is lost by keeping the
     * `.`-shaped confusions — `v1.2` against `v1.2.`, and the `..` a reader's
     * client may normalise — out of the set entirely.
     */
    private const PATTERN = '/^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$/';

    /**
     * The segment §8.2.6's default convention puts in front of every alias.
     *
     * Reserved as an alias in its own right: a collection whose member is
     * aliased `projects` serves at `/projects/projects/`, which is legal and
     * is the kind of URL that makes an operator doubt the one above it.
     */
    public const CONVENTION_SEGMENT = 'projects';

    /**
     * 🛑 Segments an alias may never be.
     *
     * §7.3's two reserved first segments, §8.6.10's version-agnostic prefix
     * — which sits in the same path position under the `alias` convention —
     * and the convention's own literal. The language-code shape is a rule
     * rather than a list and is applied separately.
     *
     * @var list<string>
     */
    public const RESERVED = ['_', '.well-known', 'page', self::CONVENTION_SEGMENT];

    /**
     * Refuse an alias that cannot be a path segment here.
     *
     * The version-slug collision is **not** checked — it needs a database and
     * a parent project, so it lives in {@see Collections::attach()} where both
     * are in hand. This function is pure, which is what lets the dashboard,
     * the API and the Read the Docs importer all ask the same question before
     * they have a row.
     *
     * @param  string  $convention  §8.2.6's `projects` or `alias`
     *
     * @throws CollectionRefused
     */
    public static function assertUsable(string $alias, string $convention = 'projects'): void
    {
        /*
         * 🛑 Reserved before malformed, and the order is the message. `_` and
         * `.well-known` both fail the shape check too, and an operator who
         * typed one of them deliberately needs to hear that DocUp has claimed
         * the segment — not that their alias has a stray character in it,
         * which is a different fix and a wrong one.
         */
        if (in_array($alias, self::RESERVED, true)) {
            throw CollectionRefused::of(CollectionRejection::AliasReserved, $alias);
        }

        // 🛑 Only where the alias stands in the language's own position.
        if ($convention === 'alias' && VersionSlug::isLanguageCodeShaped($alias)) {
            throw CollectionRefused::of(CollectionRejection::AliasReserved, $alias);
        }

        if ($alias === '' || strlen($alias) > self::MAX_LENGTH || preg_match(self::PATTERN, $alias) !== 1) {
            throw CollectionRefused::of(CollectionRejection::AliasMalformed, $alias);
        }
    }

    /** Whether an alias would be refused, for a caller that wants no exception. */
    public static function isUsable(string $alias, string $convention = 'projects'): bool
    {
        try {
            self::assertUsable($alias, $convention);

            return true;
        } catch (CollectionRefused) {
            return false;
        }
    }
}
