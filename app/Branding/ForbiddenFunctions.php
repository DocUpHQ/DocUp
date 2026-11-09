<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

/**
 * 🛑 §8.14.2's refused CSS functions, checked before any grammar runs.
 *
 * > "Colours accept only `#rgb|#rrggbb|#rrggbbaa|rgb()|hsl()|oklch()` with
 * > bounded numerics — no `var()`, `url()`, `env()`, `attr()`, `calc()`."
 *
 * ## Why a separate check at all, when the grammars are allowlists
 *
 * Every grammar in {@see TokenGrammar} is a closed pattern, so `url(…)` could
 * not match a colour even if nothing here existed. This class is not the
 * defence; it is the **diagnosis**. §17's exit criterion is "A token value
 * containing `url(`, `var(`, `calc(` or `expression(` is rejected by the
 * grammar", and a test asserting only that *something* refused the value would
 * pass equally for a value refused as a typo. Running this first means the
 * rejection identifier names the reason, so the criterion's test is about the
 * control rather than about an accident.
 *
 * It also covers the token types whose grammars are necessarily looser than a
 * colour's — short text, a font family name — where an allowlist of characters
 * is the pattern and a function call is made of permitted characters.
 *
 * ## What it refuses beyond the five names
 *
 * - 🛑 **`expression(`**, which §8.14.9 names. Long dead in browsers, alive in
 *   every static scanner's signature set, and free to refuse.
 * - 🛑 **Backslashes**, because CSS escapes mean `\75 rl(` is `url(` and a
 *   name-matching check that did not strip escapes would miss it. No value in
 *   the registry needs one, so refusing the character is cheaper and more
 *   certain than implementing CSS's escape rules — which is the general shape
 *   of §8.14.2's "a grammar, not a filter".
 * - 🛑 **CSS comment delimiters**, for the same reason: a comment opened and
 *   closed between the `u` and the `rl(` spells `url(` to a tokeniser and not
 *   to a substring search.
 * - **Whitespace before the parenthesis**, which CSS permits for some
 *   productions and which a fixed-string search for `url(` misses. The same
 *   trap §8.15.3 names for `</head >`.
 */
final class ForbiddenFunctions
{
    /**
     * The function names refused anywhere in any token value.
     *
     * §8.14.2's five, plus `expression`. Lowercase; the check folds case.
     *
     * @var list<string>
     */
    private const NAMES = ['var', 'url', 'env', 'attr', 'calc', 'expression'];

    /**
     * Refuse the value if it carries a forbidden construct.
     *
     * @param  string  $path  the token name, for the rejection
     *
     * @throws TokenRefused
     */
    public static function assertAbsent(string $raw, string $path): void
    {
        if (str_contains($raw, '\\')) {
            throw TokenRefused::of(
                TokenRejection::ForbiddenFunction,
                $path,
                'a backslash escape: no branding value needs one, and an escape can spell a refused function',
            );
        }

        if (str_contains($raw, '/*') || str_contains($raw, '*/')) {
            throw TokenRefused::of(
                TokenRejection::ForbiddenFunction,
                $path,
                'a CSS comment delimiter, which can split a refused function name',
            );
        }

        /*
         * Whitespace between the name and the parenthesis is removed before
         * the search, so `url (…)` and `url(…)` are one case. Nothing else is
         * normalised: this is a detector, and a detector that rewrote its
         * input would be deciding what the value means.
         */
        $folded = strtolower(preg_replace('/\s+\(/', '(', $raw) ?? $raw);

        foreach (self::NAMES as $name) {
            if (str_contains($folded, $name.'(')) {
                throw TokenRefused::of(
                    TokenRejection::ForbiddenFunction,
                    $path,
                    sprintf('%s() is refused in every branding value (§8.14.2)', $name),
                );
            }
        }
    }
}
