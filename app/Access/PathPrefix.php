<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

/**
 * 🛑 §8.12.9's path matching: literal prefixes, on segment boundaries, and no
 * regex.
 *
 * > "Regex path matching MUST NOT be supported — it either destroys the edge
 * > fast path or becomes an enumeration oracle."
 *
 * 🛑 **The segment boundary is the whole of the correctness here**, and it is
 * the same mistake §18.8 records on the routing side: a mount at `api` must not
 * match `apiary/…`. A naive `str_starts_with` makes a rule written for
 * `/internal/` admit — or deny — `/internal-notes/`, and the two directions of
 * that error are "a reader sees a page they may not" and "a reader is refused a
 * page they may". Both are bugs an operator cannot see by reading their own
 * policy, because the policy says `/internal/`.
 *
 * Phase 20's `RegexGuard` is the other half of this pair and the contrast is
 * deliberate: redirects accept regex behind six controls because a wrong
 * redirect is a wrong page, while access rules refuse it outright because a
 * wrong access rule is a disclosure.
 */
final class PathPrefix
{
    /**
     * Whether a prefix covers a path.
     *
     * An empty prefix, or `/`, covers everything — which is how a rule says
     * "the whole version".
     *
     * @param  string  $prefix  normalised, with a leading slash
     * @param  string  $path  normalised, with a leading slash
     */
    public static function covers(string $prefix, string $path): bool
    {
        $prefix = self::normalise($prefix);
        $path = self::normalise($path);

        if ($prefix === '/') {
            return true;
        }

        if ($path === $prefix) {
            return true;
        }

        /*
         * 🛑 The boundary. `/internal` covers `/internal/x` and `/internal`
         * itself, and does not cover `/internal-notes`. Written as "the prefix
         * followed by a slash" rather than as a length comparison, because that
         * is the property, and a length comparison is how the off-by-one gets
         * in.
         */
        return str_starts_with($path, rtrim($prefix, '/').'/');
    }

    /**
     * 🛑 Refuse a pattern that is trying to be a regex (§8.12.9).
     *
     * Refused by **shape** at write time rather than by being silently treated
     * as a literal. An operator who writes `^/internal/.*$` has written a rule
     * they believe restricts something; stored as a literal prefix it matches
     * no path at all, so the section they meant to protect is governed by
     * whatever rule comes next — a fail-open produced by politeness.
     *
     * @throws PolicyRefused
     */
    public static function assertLiteral(string $pattern): void
    {
        if ($pattern === '') {
            return;
        }

        /*
         * The metacharacters that mean somebody expected a pattern language.
         * `-`, `.` and `_` are absent because they are ordinary in a URL path;
         * `*` is included because a glob is the other thing operators try, and
         * §8.12.9 refuses that too — a rule is a prefix, and a prefix already
         * means "and everything under it".
         */
        foreach (['^', '$', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|', '\\'] as $metacharacter) {
            if (str_contains($pattern, $metacharacter)) {
                throw PolicyRefused::of(
                    RequirementRejection::RegexPathPattern,
                    '🛑 §8.12.9 forbids regex path matching; `'.$metacharacter.'` is not a path character',
                );
            }
        }

        if (! str_starts_with($pattern, '/')) {
            throw PolicyRefused::of(
                RequirementRejection::MalformedSelector,
                'a path pattern is relative to a component mount and starts with `/`',
            );
        }
    }

    /** A leading slash, no trailing slash, and `/` for the root. */
    private static function normalise(string $path): string
    {
        if ($path === '' || $path === '/') {
            return '/';
        }

        return '/'.trim($path, '/');
    }
}
