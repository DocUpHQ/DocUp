<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * §8.16.3's "−10…+10 per-page rank honouring `search.ranking` and
 * `search.ignore` from §8.4.2".
 *
 * ## 🛑 Read the Docs compatibility is value compatibility, not key compatibility
 *
 * §8.4.2 requires a "key- **and value**-compatible superset of
 * `.readthedocs.yaml` v2", and `search.{ranking,ignore}` is in its list of
 * preserved keys. Three behaviours of Read the Docs' own implementation are
 * therefore copied deliberately rather than improved on:
 *
 * 1. **The last matching pattern wins**, not the first and not the most
 *    specific. A project that writes `api/*: -1` then `api/v2/*: 4` expects
 *    `api/v2/index.html` to rank +4, and "most specific wins" would give the
 *    same answer here while disagreeing on a pair of patterns where neither
 *    contains the other. Copying the rule keeps a migrated config's behaviour
 *    identical instead of nearly identical.
 * 2. **`*` crosses `/`**, because Read the Docs matches with Python's `fnmatch`
 *    and that is what it does there. `api/*` matching `api/v2/index.html` is
 *    the behaviour every existing config was written against.
 * 3. **The default ignore list is not empty.** Read the Docs ships
 *    `search.html`, `search/index.html`, `404.html` and `404/index.html`, and a
 *    migrating project that never wrote an `ignore:` key still expects its
 *    404 page not to be a search result. 🛑 A project that writes its own
 *    `ignore:` **replaces** the defaults, which is also Read the Docs'
 *    behaviour — so `ignore: [internal/*]` makes `404.html` searchable again,
 *    and that is on the author rather than a surprise DocUp invents.
 *
 * Patterns are matched against the path relative to the build's `html/` root,
 * extension included: `guide/index.html`, never `/en/latest/guide/`. §8.16.5 is
 * the reason — there is no URL at index time, by design.
 */
final readonly class SearchRanking
{
    /** §8.16.3's bounds, inclusive. */
    public const int MIN_RANK = -10;

    public const int MAX_RANK = 10;

    /**
     * Read the Docs' own default `search.ignore`.
     *
     * 🛑 Copied verbatim from the upstream default rather than reasoned out, so
     * that a migrated project behaves the same. A generator's search page
     * indexing itself is the specific thing it prevents: Material's
     * `search.html` contains every term on the site in its template, so it
     * matches every query and outranks the page the reader wanted.
     */
    public const array DEFAULT_IGNORE = [
        'search.html',
        'search/index.html',
        '404.html',
        '404/index.html',
    ];

    /**
     * @param  list<array{0: string, 1: int}>  $ranking  pattern and rank, in
     *                                                   declaration order —
     *                                                   a list and not a map,
     *                                                   because "the last match
     *                                                   wins" needs the order
     *                                                   and a PHP array keyed
     *                                                   by pattern would also
     *                                                   silently merge
     *                                                   duplicates
     * @param  list<string>  $ignore
     */
    private function __construct(
        private array $ranking,
        private array $ignore,
    ) {}

    /** Nothing declared: every page ranks 0 and only the defaults are ignored. */
    public static function none(): self
    {
        return new self([], self::DEFAULT_IGNORE);
    }

    /**
     * From a build's stored `search:` block, as `DocupConfig::search()` returns
     * it.
     *
     * 🛑 Hostile input. The block came from a repository's own YAML, so every
     * value is checked rather than cast: a rank of `"-999"` is clamped, a rank
     * of `true` is ignored, a pattern that is an array is skipped, and a
     * pattern long enough to be a regex denial of service is truncated. §8.4's
     * parser has already refused a malformed document; what reaches here is a
     * *well-formed* document saying something unreasonable.
     *
     * @param  array<array-key, mixed>|null  $search
     */
    public static function fromConfig(?array $search): self
    {
        if ($search === null || $search === []) {
            return self::none();
        }

        $ranking = [];
        $rankingBlock = $search['ranking'] ?? null;

        if (is_array($rankingBlock)) {
            foreach ($rankingBlock as $pattern => $rank) {
                if (! is_string($pattern)) {
                    continue;
                }

                $pattern = self::pattern($pattern);

                if ($pattern === '') {
                    continue;
                }

                /*
                 * `is_int` and not `is_numeric`: a YAML author writing `-1`
                 * gets an int from the parser, and a string that happens to
                 * look numeric reached here by some other route — a quoted
                 * value, a template substitution — which is worth ignoring
                 * rather than guessing at. `true` is not a rank.
                 */
                if (is_int($rank)) {
                    $ranking[] = [$pattern, self::clamp($rank)];
                }
            }
        }

        $ignore = [];
        $ignoreBlock = $search['ignore'] ?? null;

        if (is_array($ignoreBlock)) {
            foreach ($ignoreBlock as $pattern) {
                if (is_string($pattern)) {
                    $pattern = self::pattern($pattern);

                    if ($pattern !== '') {
                        $ignore[] = $pattern;
                    }
                }
            }
        }

        /*
         * 🛑 An `ignore:` key that is present but empty — `ignore: []` — is an
         * author saying "index everything", and it must not silently fall back
         * to the defaults. `array_key_exists` and not `$ignore === []`, because
         * a declared list of four unusable patterns is also an author who
         * declared something.
         */
        $declaredIgnore = is_array($ignoreBlock) || array_key_exists('ignore', $search);

        return new self($ranking, $declaredIgnore ? $ignore : self::DEFAULT_IGNORE);
    }

    /** §8.16.3's bounds, applied. */
    public static function clamp(int $rank): int
    {
        return max(self::MIN_RANK, min(self::MAX_RANK, $rank));
    }

    /**
     * 🛑 Whether this page is excluded from the index entirely.
     *
     * @param  string  $path  relative to the build's `html/` root
     */
    public function ignores(string $path): bool
    {
        foreach ($this->ignore as $pattern) {
            if (self::matches($pattern, $path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The rank for one page, last matching pattern winning.
     *
     * @param  string  $path  relative to the build's `html/` root
     */
    public function rankFor(string $path): int
    {
        $rank = 0;

        foreach ($this->ranking as [$pattern, $value]) {
            if (self::matches($pattern, $path)) {
                $rank = $value;
            }
        }

        return $rank;
    }

    /**
     * The declared patterns, for the operator UI and `doctor`.
     *
     * @return array{ranking: list<array{pattern: string, rank: int}>, ignore: list<string>}
     */
    public function describe(): array
    {
        return [
            'ranking' => array_map(
                static fn (array $entry): array => ['pattern' => $entry[0], 'rank' => $entry[1]],
                $this->ranking,
            ),
            'ignore' => $this->ignore,
        ];
    }

    /**
     * One glob, matched Read-the-Docs style.
     *
     * 🛑 Translated to a regex by hand rather than passed to `fnmatch`, for two
     * reasons. PHP's `fnmatch` is **not available on every platform** (it is
     * absent on some Windows builds and the manual says so), and it brings
     * character classes and escapes whose behaviour differs between libc
     * implementations — so the same `.docup.yaml` would rank differently on two
     * installations. This translation understands exactly `*` and `?`, treats
     * every other character as a literal, and is therefore the same everywhere.
     *
     * 🛑 There is no backtracking to blow up: the output alternates literal
     * runs with `.*` and `.`, which is linear. `App\Redirects` has the general
     * version of this concern and a §8.11.4 guard for the case where a pattern
     * really is a regex; here no pattern ever becomes one.
     */
    private static function matches(string $pattern, string $path): bool
    {
        $regex = '';

        foreach (str_split($pattern) as $character) {
            $regex .= match ($character) {
                '*' => '.*',
                '?' => '.',
                default => preg_quote($character, '#'),
            };
        }

        return preg_match('#^'.$regex.'$#', $path) === 1;
    }

    /**
     * A pattern, normalised and bounded.
     *
     * Leading `/` and `./` are stripped so that `/404.html` and `404.html`
     * behave alike — the one thing an author writing a path-shaped pattern gets
     * wrong, and a silent non-match is an invisible failure.
     */
    private static function pattern(string $pattern): string
    {
        $pattern = trim($pattern);
        $pattern = ltrim($pattern, '/');

        while (str_starts_with($pattern, './')) {
            $pattern = substr($pattern, 2);
        }

        return substr($pattern, 0, 255);
    }
}
