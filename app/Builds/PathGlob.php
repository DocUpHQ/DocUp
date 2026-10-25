<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

/**
 * §8.5.4's and §8.6.8's changed-path globs.
 *
 * 🛑 Written rather than delegated to `fnmatch`, for two reasons that are
 * both about being able to state the semantics. `fnmatch` is a libc wrapper
 * and is **not available on every PHP build** — it is absent on Windows
 * before 8.4 — so a rule that worked on the operator's laptop could silently
 * not exist in production. And `fnmatch` has no `**`: with `FNM_PATHNAME`,
 * `docs/*` stops at the first slash and there is no way to say "everything
 * under docs", which is the only glob anybody actually writes.
 *
 * The grammar, which is the one `.gitignore` and every CI system use:
 *
 * | Pattern | Matches |
 * |---|---|
 * | `**`  | any characters, `/` included |
 * | `*`   | any characters except `/` |
 * | `?`   | exactly one character except `/` |
 * | other | itself, literally |
 *
 * `docs/**` matches `docs/index.md` and `docs/a/b/c.md`, and does not match
 * `docsite/index.md` — the slash is part of the pattern. A trailing `/**`
 * additionally matches the directory's own path (`docs`), so a rule written
 * for a directory does not miss the push that created it.
 */
final readonly class PathGlob
{
    /**
     * Whether any of the paths matches any of the globs.
     *
     * @param  list<string>  $globs
     * @param  list<string>  $paths
     */
    public static function anyMatches(array $globs, array $paths): bool
    {
        foreach ($globs as $glob) {
            $pattern = self::toRegex($glob);

            foreach ($paths as $path) {
                if (preg_match($pattern, $path) === 1) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Compile one glob to an anchored PCRE.
     *
     * 🛑 Every character outside the grammar is escaped with
     * `preg_quote`, one character at a time. A glob is operator input, and
     * an unescaped `.` would make `docs/*.md` match `docsXmd`; an unescaped
     * `(` would make the whole rule a PCRE compile error, which
     * `preg_match` reports by returning `false` — a value that is falsy, so
     * a broken rule would read as "did not match" and build everything.
     */
    public static function toRegex(string $glob): string
    {
        $regex = '';
        $length = strlen($glob);

        for ($i = 0; $i < $length; $i++) {
            $char = $glob[$i];

            if ($char === '*') {
                if ($i + 1 < $length && $glob[$i + 1] === '*') {
                    $regex .= '.*';
                    $i++;

                    continue;
                }

                $regex .= '[^/]*';

                continue;
            }

            if ($char === '?') {
                $regex .= '[^/]';

                continue;
            }

            $regex .= preg_quote($char, '#');
        }

        /*
         * A trailing `/**` also matches the directory itself, so a rule
         * written as `docs/**` is not defeated by a push whose only changed
         * path is `docs`. Expressed by making the final `/.*` optional
         * rather than by a second pattern, so there is one regex per glob.
         */
        if (str_ends_with($glob, '/**')) {
            $regex = substr($regex, 0, -strlen('/.*')).'(?:/.*)?';
        }

        return '#^'.$regex.'$#';
    }
}
