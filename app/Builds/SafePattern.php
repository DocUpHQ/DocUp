<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Composition\VersionLabel;

/**
 * An operator-supplied regular expression, matched without trusting it.
 *
 * §8.5.4 and §8.6.8 both let an operator write a "branch/tag regex" and a
 * "commit message regex". Those are arbitrary PCRE from a human, which
 * brings two problems that a bare `preg_match` handles badly.
 *
 * 🛑 **A pattern can fail to compile.** `preg_match` then emits a warning
 * and returns `false` — which is falsy, so `if (preg_match(...))` reads a
 * broken rule as "did not match". For a `skip` rule that means a build that
 * should not have happened; for a `build` rule it means one that should
 * have. Either way nothing says so, which is why patterns are validated on
 * write and a compile failure at read time is explicit here.
 *
 * 🛑 **A pattern can backtrack catastrophically.** `(a+)+$` against sixty
 * `a`s is seconds of CPU per evaluation, and these are evaluated on the
 * webhook path. PCRE's own `pcre.backtrack_limit` bounds it and makes
 * `preg_match` return `false`, which lands in the same branch as a compile
 * failure: treated as **no match**, so the rule is passed over and the next
 * one is tried.
 *
 * Passing over is the safe direction. An unmatched rule falls through to the
 * next, and a push that matches nothing builds (see
 * {@see SkipRuleEvaluator}), so the worst outcome of a pathological pattern
 * is a build that was not needed. The reverse default — treat an error as a
 * match — would let one bad regex stop a project building for ever.
 *
 * The expression is matched as a **substring search**, not anchored, which
 * is what an operator writing `^release/` or `docs` expects from every other
 * tool that asks them for a regex.
 */
final readonly class SafePattern
{
    /**
     * 🛑 Delimited with `#` and given no modifiers.
     *
     * No `/.../x`, no `e` (removed in PHP 7 but worth naming), and in
     * particular no modifier the operator can choose: the pattern is
     * **data** and this is the only place the delimiters are decided. A
     * pattern wrapped in whatever the operator typed would let them supply
     * `/.../e`-shaped input to any future code that forwarded it.
     */
    private const DELIMITER = '#';

    /** Whether a pattern compiles, for validation on write. */
    public static function isValid(string $pattern): bool
    {
        return @preg_match(self::compile($pattern), '') !== false;
    }

    /**
     * Whether the subject contains a match.
     *
     * A pattern that cannot compile, or that exhausts PCRE's limits,
     * returns false — see the class note for why that direction is the safe
     * one.
     */
    public static function matches(string $pattern, string $subject): bool
    {
        return @preg_match(self::compile($pattern), $subject) === 1;
    }

    /**
     * The first capture group of a match, or null.
     *
     * §10.2's `version_label_strategy = 'regex'` asks an operator for a
     * pattern whose job is to *extract* rather than to decide — "the version
     * label is whatever this captures from the tag". Returning null for a
     * pattern that does not match, that has no group, or that cannot
     * compile keeps every failure in one branch, which is what
     * {@see VersionLabel} treats as "this ref has no
     * label".
     *
     * A whole-match fallback is deliberately **absent**. A pattern with no
     * group would then label every matching ref with the ref itself, which
     * reads as success and is how a branch ends up in a version ordering.
     */
    public static function firstGroup(string $pattern, string $subject): ?string
    {
        $matched = @preg_match(self::compile($pattern), $subject, $groups);

        if ($matched !== 1 || ! isset($groups[1])) {
            return null;
        }

        return $groups[1];
    }

    /** Whether any subject contains a match. */
    public static function matchesAny(string $pattern, string ...$subjects): bool
    {
        $compiled = self::compile($pattern);

        foreach ($subjects as $subject) {
            if (@preg_match($compiled, $subject) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * Wrap the operator's expression in delimiters it cannot escape from.
     *
     * 🛑 Only an **unescaped** delimiter is escaped, which is why this
     * counts backslashes rather than calling `str_replace`. A blanket
     * replace turns the operator's own `\#` — a literal hash, which they
     * write for `#\d+` against a commit message — into `\\#`, a literal
     * backslash followed by the closing delimiter, and the pattern ends
     * early. The run length decides: an odd number of backslashes before a
     * `#` means it is already escaped.
     */
    private static function compile(string $pattern): string
    {
        $escaped = '';
        $backslashes = 0;

        for ($i = 0, $length = strlen($pattern); $i < $length; $i++) {
            $char = $pattern[$i];

            if ($char === self::DELIMITER && $backslashes % 2 === 0) {
                $escaped .= '\\';
            }

            $escaped .= $char;
            $backslashes = $char === '\\' ? $backslashes + 1 : 0;
        }

        return self::DELIMITER.$escaped.self::DELIMITER;
    }
}
