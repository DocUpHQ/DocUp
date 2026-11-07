<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Redirects;

/**
 * §8.11.2's six rule types.
 *
 * > "Rule types MUST include exact, prefix with `:splat`, version-agnostic
 * > page, clean-URL, HTML-extension and regular expression, with status codes
 * > 301, 302, 307 and 308 and explicit ordering. (Read the Docs supports only
 * > 301/302.)"
 *
 * 🛑 The six are not six syntaxes for one idea. Four of them exist because the
 * same reorganisation looks different depending on **which axis moved**:
 *
 *   - a page moved                     → `exact`
 *   - a section moved                  → `prefix`, with `:splat`
 *   - a page moved in **every** version → `version_agnostic`
 *   - the generator's URL style changed → `clean_url` / `html_extension`
 *
 * An operator who has only `exact` and `regex` — which is roughly Read the
 * Docs — writes the third as one rule per version and the fourth as a regex,
 * and both go stale the next time a version is added.
 */
enum RedirectKind: string
{
    /** One path to one path. The whole of it, matched byte for byte. */
    case Exact = 'exact';

    /**
     * A path prefix, with the remainder available to the target as `:splat`.
     *
     * `/guide/:splat` → `/handbook/:splat` moves a section and keeps every
     * page under it. The splat is the rest of the path including nothing:
     * `/guide/` itself matches with an empty splat.
     */
    case Prefix = 'prefix';

    /**
     * A page that moved in **every** version at once.
     *
     * The pattern and the target are written without the language and
     * version segments, and the engine supplies the ones the request
     * carried. One rule covers `/en/v1/`, `/en/v2/` and `/ja/latest/`, and
     * goes on covering `/en/v3/` the day it exists.
     *
     * 🛑 This is the type Read the Docs has no equivalent of, and it is the
     * one a real reorganisation needs most: a documentation set that renames
     * a page renames it everywhere, and a per-version rule set is a thing
     * somebody has to remember to extend.
     */
    case VersionAgnostic = 'version_agnostic';

    /**
     * `/a/b.html` → `/a/b/`, for a project that switched its generator to
     * directory URLs.
     *
     * The pattern is a scope — a path prefix the rule applies under, or `/`
     * for the whole project — and the target is computed, not written.
     */
    case CleanUrl = 'clean_url';

    /** The reverse: `/a/b/` → `/a/b.html`, for a project that switched away. */
    case HtmlExtension = 'html_extension';

    /**
     * A PCRE pattern, with `$1`-style back-references in the target.
     *
     * 🛑 Contained by {@see RegexGuard}, and §8.11.4 explains at length why
     * the containment is six separate controls rather than a timeout.
     */
    case Regex = 'regex';

    /**
     * Whether this kind computes its target rather than being given one.
     *
     * The two URL-style rules take a scope and derive the target from the
     * request, so a `to_target` for them is a scope marker and not a
     * destination. Asked here so no call site has to remember.
     */
    public function derivesTarget(): bool
    {
        return $this === self::CleanUrl || $this === self::HtmlExtension;
    }

    /**
     * Whether this kind's pattern and target omit the `{lang}/{version}`
     * segments, which the engine then supplies from the request.
     */
    public function isVersionRelative(): bool
    {
        return $this === self::VersionAgnostic;
    }
}
