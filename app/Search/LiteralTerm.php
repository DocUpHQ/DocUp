<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * 🛑 §8.16.12's degradation, in **one** place so two drivers cannot disagree.
 *
 * > §8.16.12: "Syntax a driver cannot support — typo tolerance, prefix,
 * > proximity, fuzziness — MUST be documented per driver in a published
 * > capability matrix and MUST degrade to a literal term rather than erroring."
 *
 * A reader who types `~authentication` must get the same answer on both
 * engines, and that is only true if both reduce the term the same way. The
 * first version left each driver to strip its own syntax — MySQL's boolean-mode
 * operators in one, Meilisearch's exclusion operator in the other — and
 * `~nuterm` then found the document on MySQL and nothing on Meilisearch,
 * because `~` is an operator there and a literal character here.
 *
 * That made §8.16.12's "the identical suite passes on both engines" false for
 * exactly the clause §8.16.12 is about. One function, both drivers, and
 * `SearchArchitectureTest` asserts neither driver strips operators of its own.
 *
 * ## 🛑 Why the terms are not reduced in the parser instead
 *
 * {@see QueryParser} keeps a term as the reader typed it, because the raw term
 * is what §8.16.10's round-trip needs and because a parser that silently
 * rewrote `C++` to `C` would be making a search decision on the reader's
 * behalf before anything had looked at an index. The reduction belongs at the
 * engine boundary, where it is one driver's syntax being neutralised rather
 * than the query being rewritten.
 */
final readonly class LiteralTerm
{
    /**
     * Every character that is syntax in **either** engine.
     *
     * The union, not each driver's own set — which is the whole point. MySQL's
     *
     * boolean mode uses `+ - > < ( ) ~ * @ "`, Meilisearch uses `-` and `"`,
     * and the backslash is here because it is an escape in both and a lone one
     * is a parse hazard in neither's favour.
     *
     * 🛑 Removed rather than escaped. MySQL's boolean mode has **no** escape
     * for its operators, so there is nothing to escape them to — and a `-`
     * surviving into a boolean expression is a reader able to **exclude**
     * documents a filter had just included, which is the one outcome that is
     * not merely a worse search.
     */
    private const array OPERATORS = ['+', '-', '~', '<', '>', '(', ')', '*', '@', '"', '\\', '^'];

    /**
     * A term or phrase with both engines' syntax removed.
     *
     * Returns `''` when nothing is left, which the drivers drop — a query
     * reduced entirely to operators matches nothing, which is §8.16.12's
     * "rather than erroring".
     */
    public static function of(string $term): string
    {
        $term = str_replace(self::OPERATORS, ' ', $term);

        return trim((string) preg_replace('/\s+/u', ' ', $term));
    }

    /**
     * 🛑 A **term** as the words it reduces to — which may be more than one.
     *
     * Removing an operator can split a word: `nuterm^5` is `nuterm` and `5`,
     * and `a-b` is `a` and `b`. The characters are replaced with a space rather
     * than deleted for the reason `QueryParser` gives about control characters
     * — joining two tokens into one invents a word nobody typed, and a defeated
     * filter is worse than a failed search — so the result has to be read as
     * several words.
     *
     * Both drivers then require **all** of them, which is §8.16.12's implicit
     * AND applied consistently: `nuterm^5` behaves exactly like
     * `nuterm 5`, and `foo OR bar` exactly like `foo OR bar`. The alternative —
     * keeping the first word and dropping the rest — would make the engines
     * agree while silently discarding part of the query.
     *
     * 🛑 This is where the two engines last disagreed. With the whitespace left
     * inside one term, MySQL's boolean mode read `+nuterm 5` as "nuterm
     * required, 5 optional" and matched, while Meilisearch's `all` strategy
     * required both and did not. Splitting here makes them identical.
     *
     * @return list<string>
     */
    public static function wordsOf(string $term): array
    {
        $reduced = self::of($term);

        if ($reduced === '') {
            return [];
        }

        $words = preg_split('/\s+/u', $reduced);

        return is_array($words) ? array_values(array_filter($words, static fn (string $w): bool => $w !== '')) : [];
    }
}
