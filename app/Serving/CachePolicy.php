<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

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
