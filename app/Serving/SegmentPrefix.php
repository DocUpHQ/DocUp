<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * 🛑 §7.3's "longest match, on a segment boundary", once.
 *
 * The grammar applies this rule at two levels — `domain_mount(path_prefix)` and
 * `component_mount(mount_path)` — and it was implemented twice: once to *choose*
 * a prefix and once to *consume* it. That left each caller carrying a defensive
 * branch for the case where the two disagreed, and those branches were
 * unreachable, which is how the resolver's coverage sat below §8.9.1's
 * threshold. Dead code guarding against a disagreement is worse than one
 * implementation that cannot disagree with itself.
 *
 * So matching and consuming are the same operation here: the result carries both
 * the prefix that won and what is left after it.
 *
 * **Why the boundary matters.** A mount at `api` must not match a request for
 * `apiary/guide.html`. A plain `str_starts_with` would, and on a shared domain
 * that is one project's portal mount quietly swallowing another project's URLs
 * — with the symptom appearing as one team's documentation showing up under
 * another team's path.
 */
final class SegmentPrefix
{
    /**
     * The longest prefix matching on a segment boundary, and the remainder.
     *
     * @param  list<string>  $prefixes  candidates; `''` matches everything
     * @param  string  $path  no leading slash
     * @return array{0: string, 1: string}|null the winning prefix and the
     *                                          remainder after it, or null when
     *                                          nothing matched
     */
    public static function longest(array $prefixes, string $path): ?array
    {
        $best = null;
        $bestLength = -1;

        foreach ($prefixes as $index => $prefix) {
            $length = strlen($prefix);

            // A shorter candidate can never beat a longer one already found,
            // so the comparison runs before any string work.
            if ($length <= $bestLength) {
                continue;
            }

            if ($prefix === '') {
                // The root prefix matches everything and is the shortest
                // possible match, so it only wins when nothing longer does.
                $best = $index;
                $bestLength = 0;

                continue;
            }

            if (! str_starts_with($path, $prefix)) {
                continue;
            }

            /*
             * The match must end at the end of the path or immediately before a
             * separator. `?? '/'` treats the end of the string as a boundary,
             * which is what makes a request for exactly `api` match a mount at
             * `api`.
             */
            if (($path[$length] ?? '/') !== '/') {
                continue;
            }

            $best = $index;
            $bestLength = $length;
        }

        if ($best === null) {
            return null;
        }

        $prefix = $prefixes[$best];

        if ($prefix === '') {
            return ['', $path];
        }

        // Consuming the prefix cannot fail: it matched on a boundary above, so
        // the path is either exactly the prefix or the prefix plus a separator.
        return [$prefix, $path === $prefix ? '' : substr($path, strlen($prefix) + 1)];
    }
}
