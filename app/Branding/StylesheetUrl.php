<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

use App\Serving\CachePolicy;

/**
 * 🛑 §8.14.4's content-addressed stylesheet path, in one place.
 *
 * > "Each theme revision MUST publish as an immutable content-addressed
 * > stylesheet with `max-age=31536000, immutable`, so 500 projects cost one
 * > bundle plus 500 small files and a token edit mints a new URL with nothing
 * > to purge."
 *
 * ## 🛑 Relative, and that is the requirement rather than a convenience
 *
 * The path is site-relative, so it resolves against whichever origin served
 * the page: the dashboard for the dashboard, `docs.acme.example` for that
 * tenant's documentation. §8.14.10 requires `font-src 'self'` and a strict
 * dashboard CSP (§8.14.16), and a stylesheet on a third origin would need both
 * to be widened. §8.14.10 widens `img-src` to the asset host and nothing else,
 * deliberately: an image can be sandboxed on another origin, a stylesheet
 * cannot.
 *
 * ## 🛑 §7.3's never-cacheable rule, and the one carve-out this phase needs
 *
 * §7.3 reserves `/_/` and lists `/_/theme` and `/_/assets` among the names it
 * reserves — so this is where the specification intends theme bytes to live.
 * It also says "Nothing under `/_/` is publicly cacheable", which §8.14.4
 * contradicts for exactly this path.
 *
 * The contradiction is resolved in §8.14.4's favour and the amendment is
 * recorded in the build log, because the reason behind §7.3's rule does not
 * reach here. Everything else under `/_/` is request-scoped and
 * reader-dependent — the addons payload, search, the authz subrequest,
 * downloads — so a shared cache entry would be one reader's answer served to
 * another. A theme stylesheet has no reader dimension at all: the URL **is** a
 * hash of the bytes, so a cached copy cannot be stale and cannot belong to
 * somebody else. §7.3 already carries three carve-outs of the same shape under
 * `/.well-known/`, for the JWKS document, the epoch feed and the ACME
 * challenge.
 *
 * 🛑 §9.3.2's gate is untouched. That requirement is about **private
 * documentation** entering a shared cache, and the public directive is still
 * constructed only by {@see CachePolicy} — which is where the
 * architecture test looks.
 */
final class StylesheetUrl
{
    /** The reserved prefix. §7.3 makes `/_/theme` unmountable. */
    public const PREFIX = '/_/theme';

    /** The stylesheet for a resolved theme's content hash. */
    public static function forHash(string $contentHash): string
    {
        return self::PREFIX.'/'.$contentHash.'.css';
    }

    /** The self-hosted font path a `@font-face` names (§8.14.10's `font-src 'self'`). */
    public static function forFont(string $contentHash): string
    {
        return self::PREFIX.'/font/'.$contentHash.'.woff2';
    }
}
