<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

use App\Branding\StylesheetUrl;
use App\Readers\Grants\GrantKeys;

/**
 * 🛑 The single three-way public check (§9.3.2).
 *
 * §9.3.2: "An architecture test MUST forbid any code path setting a public CDN
 * cache directive outside the single three-way public check (project public ∧
 * version public ∧ rule publicly cacheable)."
 *
 * So this is that check, and it is the only thing in the codebase that may
 * construct a publicly cacheable response. The architecture test asserts the
 * sole call site; this class's job is to make that assertion meaningful by
 * being small enough to read in one sitting.
 *
 * **Why a conjunction and not a precedence.** Each of the three can only
 * narrow. A public project with a private version is private; a public version
 * under a reader-policy rule that is not publicly cacheable is private. Writing
 * it as `&&` rather than as a chain of overrides means there is no order in
 * which the answers are considered, and therefore no ordering bug — the
 * failure mode in an override chain is that the last writer wins and somebody
 * adds a fourth input at the wrong end.
 *
 * Phase 04 serves public documentation only (§17: "Authentication beyond public"
 * is out of scope), so the third input is constant `true` for now. It is a
 * parameter rather than omitted because §17 puts the lattice columns on tables
 * created in P03 and P04 "rather than being added here" — the shape has to be
 * right before anything serves, or the check is retrofitted onto a live path.
 */
final class CachePolicy
{
    /**
     * How long a browser may keep a public document.
     *
     * Short, because the browser cache cannot be purged. §8.9.10's epoch-in-the
     * -key makes a failed CDN purge degrade to stale public HTML for this long
     * and never to wrong routing, so this number is the worst case a reader
     * sees after a publish — not the worst case for correctness.
     */
    private const BROWSER_MAX_AGE = 60;

    /** How long the edge may keep it. Longer, because the edge can be purged. */
    private const CDN_MAX_AGE = 86_400;

    /**
     * Decide the cache directives for one response.
     *
     * @param  bool  $projectIsPublic  `projects.visibility === 'public'` (§8.2.10)
     * @param  bool  $versionIsPublic  `project_versions.visibility === 'public'`
     * @param  bool  $rulePubliclyCacheable  §12's reader policy; true when no
     *                                       rule restricts the response
     * @param  list<string>  $cacheTags  §9.3.3's scopes: mount, project,
     *                                   version, build, theme
     */
    public static function decide(
        bool $projectIsPublic,
        bool $versionIsPublic,
        bool $rulePubliclyCacheable,
        array $cacheTags = [],
    ): CacheDirectives {
        /*
         * 🛑 The whole check, in one expression. Anything that is not all three
         * is private, and private is the default rather than the exception —
         * so a fourth input added later that somebody forgets to wire in makes
         * responses private, not public.
         */
        if (! ($projectIsPublic && $versionIsPublic && $rulePubliclyCacheable)) {
            return CacheDirectives::private();
        }

        return CacheDirectives::publiclyCacheable(
            maxAge: self::BROWSER_MAX_AGE,
            cdnMaxAge: self::CDN_MAX_AGE,
            cacheTags: $cacheTags,
        );
    }

    /**
     * How long the edge may keep a 404 (§8.11.8).
     *
     * 🛑 Short, and much shorter than content. A 404 is a claim about
     * **absence**, and absence is the one answer a publish makes wrong:
     * the page that did not exist a minute ago is the page somebody just
     * added. Sixty seconds at the edge absorbs a flood of one URL and
     * bounds how long a newly published page can be denied.
     */
    private const NOT_FOUND_CDN_MAX_AGE = 60;

    /** And the browser keeps it for less, because a browser cache cannot be purged. */
    private const NOT_FOUND_BROWSER_MAX_AGE = 15;

    /**
     * 🛑 §8.11.8's edge-cacheable 404 — for an absence that is genuinely an
     * absence.
     *
     * > "404 responses MUST be edge-cacheable with a short TTL, and a
     * > progressive per-source penalty-box limiter MUST apply to 404 bursts
     * > and search. Read the Docs' June 2026 DDoS targeted exactly these
     * > paths."
     *
     * **The distinction this method exists to enforce** is between a 404
     * that means "there is nothing here" and a 404 that means "there is
     * something here and you may not see it". §12 answers the second with
     * a 404 on purpose, and caching *that* publicly would serve one
     * reader's refusal to a member who should have been let in — and would
     * confirm, to anyone watching the cache, which paths are the
     * interesting ones.
     *
     * So the same three-way check as {@see self::decide()} governs, plus
     * one addition: a rejection that fired **before any project was
     * identified** is unconditionally cacheable, because there was no
     * tenant for it to be about. An unknown hostname is not somebody's
     * private page.
     *
     * @param  bool|null  $projectIsPublic  null when no project was reached
     * @param  bool|null  $versionIsPublic  null when no version was reached
     */
    public static function forAbsence(
        ?bool $projectIsPublic = null,
        ?bool $versionIsPublic = null,
        bool $rulePubliclyCacheable = true,
    ): CacheDirectives {
        /*
         * Nothing was identified: no host, no mount, no project. There is
         * no tenant this answer is about, so there is nothing to leak and
         * the edge may absorb the flood.
         */
        if ($projectIsPublic === null && $versionIsPublic === null) {
            return self::absence();
        }

        /*
         * 🛑 Anything partially identified is held to the full check, and
         * `null` counts as **not public**. A project reached without a
         * version is a 404 about a project, and if that project is private
         * the 404 is an access decision wearing an absence's clothes.
         */
        if ($projectIsPublic !== true || $versionIsPublic !== true || ! $rulePubliclyCacheable) {
            return CacheDirectives::private();
        }

        return self::absence();
    }

    /**
     * 🛑 No cache tags, deliberately.
     *
     * §9.3.3 scopes a tag to mount, project, version, build and theme so a
     * publish can purge exactly what it changed. A 404 belongs to none of
     * those — it is about a path that has no build and no version — so a
     * tag would either be wrong or would purge content that is fine. The
     * short TTL is the invalidation instead, which is why it is short.
     */
    private static function absence(): CacheDirectives
    {
        return CacheDirectives::publiclyCacheable(
            maxAge: self::NOT_FOUND_BROWSER_MAX_AGE,
            cdnMaxAge: self::NOT_FOUND_CDN_MAX_AGE,
            cacheTags: [],
        );
    }

    /**
     * A published, versioned public contract (§8.1.11).
     *
     * 🛑 Here rather than in the controller, and that is the point of the
     * architecture test that sent it here: §9.3.2's invariant is that **one**
     * place decides public cacheability, so a second place that happened to
     * be right today is still the crack a private response eventually goes
     * through. The `.docup.yaml` schema is the first caller.
     *
     * Cacheable for a day, publicly, with no cache tags: the response carries
     * no tenant's anything — the schema describes the shape of a
     * configuration file and names no installation, no project and no host —
     * so there is nothing to scope a purge to. §8.1.11 puts the version in
     * the URL and gives the contract "a two-minor deprecation policy", which
     * means v1 never changes meaning and a v2 is a different URL; a long
     * cache is therefore correct rather than merely tolerable.
     */
    public static function forPublishedContract(): CacheDirectives
    {
        return CacheDirectives::publiclyCacheable(
            maxAge: self::CDN_MAX_AGE,
            cdnMaxAge: self::CDN_MAX_AGE,
            cacheTags: [],
        );
    }

    /**
     * §20.2's JWKS document — the second of §7.3's two `/.well-known/`
     * exceptions to "nothing under it is publicly cacheable".
     *
     * 🛑 Here for the reason {@see self::forPublishedContract()} is here, and
     * the architecture test sent this one the same way: §9.3.2's invariant is
     * that **one** place decides public cacheability. A controller writing
     * `'public, max-age=60'` by hand would be correct today and would be the
     * second place that has to stay correct forever.
     *
     * Public is right, and §8.12.11 is why: "Public-key verification lets the
     * edge verify and never mint." The document holds public keys, is identical
     * for every reader of every project on the installation, and names no
     * tenant — `grant_signing_keys` has no `organisation_id` column at all — so
     * a shared cache holding it crosses no boundary. No cache tags, for the
     * same reason the schema has none: there is nothing to scope a purge to.
     *
     * 🛑 The `max-age` is deliberately **not** this class's own CDN figure. It
     * is {@see GrantKeys::JWKS_CACHE_SECONDS}, which the
     * four-state rotation's `retiring` window is also derived from — one
     * constant, two consumers. A longer cache here without a longer retiring
     * window would strand grants at a rotation, which is exactly the failure
     * the four states exist to prevent.
     */
    public static function forGrantKeys(int $maxAge): CacheDirectives
    {
        return CacheDirectives::publiclyCacheable(
            maxAge: $maxAge,
            cdnMaxAge: $maxAge,
            cacheTags: [],
        );
    }

    /**
     * 🛑 §8.14.4's content-addressed branding bytes — a theme stylesheet, a
     * self-hosted font, an uploaded logo.
     *
     * > "Each theme revision MUST publish as an immutable content-addressed
     * > stylesheet with `max-age=31536000, immutable`, so 500 projects cost one
     * > bundle plus 500 small files and a token edit mints a new URL with
     * > nothing to purge."
     *
     * Here for the reason {@see self::forPublishedContract()} and
     * {@see self::forGrantKeys()} are here: §9.3.2's invariant is that **one**
     * place decides public cacheability, and a controller writing
     * `'public, max-age=31536000, immutable'` by hand would be a second place
     * that has to stay correct forever.
     *
     * **Why public is right.** The URL is a SHA-256 of the bytes. There is no
     * reader dimension — two readers of the same theme get the same file, and a
     * reader who has never been authorised for anything cannot construct the
     * URL without having been served a page that names it. §9.3.2's concern is
     * "private **documentation** entering a shared cache", and a design token
     * is not documentation: it is the tenant's choice of colour, which is on
     * public display in every page the theme styles.
     *
     * 🛑 **`immutable` is safe only because of the hash**, and that is the
     * whole argument. `immutable` tells a browser not to revalidate even on a
     * reload, so a mutable URL carrying it would be wrong for a year with no
     * remedy. A content-addressed URL cannot be wrong: different bytes are a
     * different URL. §8.14.4's "nothing to purge" is the same observation.
     *
     * No cache tags. A tag is a purge handle and there is nothing to purge —
     * which is the economy §8.14.4 is describing, not an omission.
     *
     * 🛑 **One divergence from §7.3, recorded rather than quietly taken.** §7.3
     * says "Nothing under `/_/` is publicly cacheable" and lists `/_/theme`
     * and `/_/assets` among its reserved names. The rule's reason — everything
     * else under `/_/` is request-scoped, so a shared entry would serve one
     * reader's answer to another — does not reach a path whose bytes are named
     * by their own hash, and §8.14.4 requires the opposite in terms. §7.3
     * already carries three carve-outs of this shape under `/.well-known/`.
     * {@see StylesheetUrl} states the amendment; the build log
     * records it.
     */
    public static function forImmutableBrandingAsset(): CacheDirectives
    {
        $configured = config('branding.immutable_max_age');
        $maxAge = is_numeric($configured) ? (int) $configured : 31_536_000;

        return CacheDirectives::publiclyCacheable(
            maxAge: $maxAge,
            cdnMaxAge: $maxAge,
            cacheTags: [],
            immutable: true,
        );
    }

    /**
     * §9.3.3's cache tags: "scoped to mount, project, version, build and theme".
     *
     * 🛑 Every tag is an opaque identifier, never a slug. A tag reaches the CDN,
     * which is a third party for most installations, and a slug there would
     * leak project names to it — and would also strand the tag when a project
     * is renamed, so a purge after a rename would miss exactly the content the
     * rename made wrong.
     *
     * @param  string|null  $themeId  null until Phase 16 assigns themes
     * @return list<string>
     */
    public static function tagsFor(
        string $mountId,
        string $projectId,
        string $versionId,
        string $buildId,
        ?string $themeId = null,
    ): array {
        $tags = [
            'm-'.$mountId,
            'p-'.$projectId,
            'v-'.$versionId,
            'b-'.$buildId,
        ];

        if ($themeId !== null) {
            $tags[] = 't-'.$themeId;
        }

        return $tags;
    }
}
