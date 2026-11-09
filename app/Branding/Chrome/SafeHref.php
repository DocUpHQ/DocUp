<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Chrome;

use App\Branding\TokenRefused;
use App\Branding\TokenRejection;

/**
 * 🛑 What a chrome link may point at (§8.14.3, §8.14.8).
 *
 * Navigation links, footer links and the announcement's one `<a>` all go
 * through here, because a link target is the one field in §8.14.3's structured
 * data that can execute code. `javascript:alert(1)` in a footer link is
 * §8.14.8's "tenant JavaScript … in portal or documentation chrome" with no
 * `<script>` involved.
 *
 * ## The rule
 *
 * A site-relative path (`/guide/intro.html`), or an absolute `http`/`https`
 * URL. Nothing else — not `mailto:`, not a protocol-relative `//host/path`, not
 * a bare `#fragment`.
 *
 * `mailto:` is refused with some regret: it is harmless and it is the only
 * omission an operator is likely to ask about. The reason is that admitting one
 * non-fetch scheme means the check is a scheme allowlist rather than a shape,
 * and a scheme allowlist is a list somebody extends. A footer that needs to
 * reach a mailbox can link to a contact page.
 *
 * `//host/path` is refused because it is the one shape that looks relative and
 * is not: a reviewer reading `//cdn.example/x` sees a path, and a browser sees
 * another origin.
 */
final class SafeHref
{
    /** The longest link target chrome will carry. */
    private const MAX_LENGTH = 2048;

    /**
     * Normalise one link target, or refuse it.
     *
     * @param  string  $path  the field name, for the rejection
     *
     * @throws TokenRefused
     */
    public static function parse(string $href, string $path): string
    {
        $href = trim($href);

        if ($href === '') {
            throw TokenRefused::of(TokenRejection::UnsafeLinkTarget, $path, 'empty');
        }

        if (strlen($href) > self::MAX_LENGTH) {
            throw TokenRefused::of(
                TokenRejection::UnsafeLinkTarget,
                $path,
                sprintf('%d bytes; the limit is %d', strlen($href), self::MAX_LENGTH),
            );
        }

        /*
         * 🛑 Control characters, and the reason is specific rather than
         * hygienic: a browser strips a newline or a tab out of a URL before
         * resolving the scheme, so `java\nscript:alert(1)` is a `javascript:`
         * URL to the browser and is not one to any check that reads the string
         * as written. This is the classic bypass of exactly this kind of
         * function, and refusing the characters is the only reading on which
         * DocUp and the browser agree.
         */
        if (preg_match('/[\x00-\x20\x7F]/', $href) === 1) {
            throw TokenRefused::of(
                TokenRejection::UnsafeLinkTarget,
                $path,
                'whitespace or a control character, which a browser strips before reading the scheme',
            );
        }

        if (str_starts_with($href, '//')) {
            throw TokenRefused::of(
                TokenRejection::UnsafeLinkTarget,
                $path,
                'a protocol-relative URL looks like a path and is another origin; write the scheme',
            );
        }

        if (str_starts_with($href, '/')) {
            return $href;
        }

        /* `~` delimits, because the pattern's own character class holds a `#`. */
        if (preg_match('~^https?://[^/?#]+~i', $href) === 1) {
            /*
             * The scheme is lowercased and the rest is left exactly as
             * written. Normalising a path or re-encoding a query would change
             * a link the operator tested, and this function's job is to refuse
             * or pass rather than to improve.
             */
            $position = (int) strpos($href, ':');

            return strtolower(substr($href, 0, $position)).substr($href, $position);
        }

        throw TokenRefused::of(
            TokenRejection::UnsafeLinkTarget,
            $path,
            'a chrome link is a /site-relative path or an http(s):// URL',
        );
    }
}
