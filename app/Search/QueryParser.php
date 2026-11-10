<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * 🛑 §8.16.12's minimum query syntax, and the one place a reader's string is
 * read.
 *
 * > §8.16.12: "The system MUST define one **minimum query syntax every
 * > `SearchEngine` driver honours**, so that 'the identical suite passes on both
 * > engines' is a meaningful claim: implicit AND between terms, exact phrase in
 * > double quotes, and the scope filters `project:<slug>[/<version>]`,
 * > `collection:<slug>` and `self:me`."
 *
 * ## 🛑 What this parser refuses to understand
 *
 * Everything else. §8.16.12 also says syntax a driver cannot support "MUST
 * degrade to a literal term rather than erroring", and that is implemented by
 * having no operators at all: `~`, `*`, `AND`, `OR`, `NOT`, `+`, `-`, `^` and a
 * bare `:` are **characters in a term**, not syntax. A reader searching for
 * `C++` gets a search for `C++`; one searching for `foo OR bar` gets a search
 * for three terms, which finds nothing and is the honest answer for an engine
 * with no OR.
 *
 * That is not laziness, it is the degradation rule: a parser that understood
 * `OR` on Meilisearch and ignored it on MySQL would make "the identical suite
 * passes on both engines" false, and the suite would be the thing that stopped
 * saying so.
 *
 * ## 🛑 And it never produces a filter
 *
 * A scope prefix becomes a {@see ScopeRequest}, which is a slug and a kind.
 * Nothing this class returns is an engine filter expression, and nothing it
 * returns can become one without {@see AuthorisedScope} agreeing — which is
 * §8.16.12's "re-derived server-side against the authorised view". The abuse
 * corpus carries the cases: a Meilisearch filter expression, a boolean-mode
 * payload and a SQL fragment in the query string are all just terms.
 */
final readonly class QueryParser
{
    /**
     * 🛑 The cap on what one query may ask for.
     *
     * §9.3.5 rate-limits search and §8.16.12 leaves the penalty box to Phase
     * 30, so this phase needs a bound that does not depend on either. A
     * thousand-term query against a FULLTEXT index is a thousand index probes
     * per matching row; the cost is real and it is paid before any limiter
     * sees a second request.
     *
     * Terms beyond the cap are **dropped**, not an error: §8.16.12's
     * degradation rule again, and a reader who pasted a paragraph into a search
     * box wants results rather than a validation message.
     */
    public const int MAX_TERMS = 16;

    /** The longest single term or phrase kept, in characters. */
    public const int MAX_TERM_LENGTH = 100;

    /** The longest query string read at all. */
    public const int MAX_QUERY_LENGTH = 512;

    /**
     * Parse a reader's query string.
     *
     * @param  string  $query  raw, exactly as it arrived
     */
    public function parse(string $query): ParsedQuery
    {
        $raw = $query;

        /*
         * 🛑 Truncate before anything else. Every loop below is bounded by the
         * string's length, and the one that is not — the quote scanner — is
         * bounded by the number of quotes in it.
         */
        if (mb_strlen($query) > self::MAX_QUERY_LENGTH) {
            $query = mb_substr($query, 0, self::MAX_QUERY_LENGTH);
        }

        /*
         * 🛑 Control characters out, including the NUL that would truncate a
         * C-level comparison and the newlines that would let a term carry a
         * second line past a log's one-line-per-entry assumption. Replaced with
         * a space rather than removed, so `a\x00b` is two terms and not the
         * term `ab` — which is the difference between a defeated filter and a
         * failed search.
         */
        $query = (string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $query);

        $terms = [];
        $phrases = [];
        $scopes = [];

        foreach ($this->split($query) as [$isPhrase, $token]) {
            if ($isPhrase) {
                $phrase = $this->normalise($token);

                if ($phrase !== '' && count($phrases) + count($terms) < self::MAX_TERMS) {
                    $phrases[] = $phrase;
                }

                continue;
            }

            $scope = $this->scopeIn($token);

            if ($scope instanceof ScopeRequest) {
                /*
                 * 🛑 A scope prefix is consumed and does NOT also become a term.
                 * Leaving it in would make `project:docup auth` search for the
                 * literal text "project:docup", which matches nothing, so every
                 * scoped query would return nothing and the scope would look
                 * like it had filtered everything out.
                 */
                $scopes[] = $scope;

                continue;
            }

            $term = $this->normalise($token);

            if ($term !== '' && count($phrases) + count($terms) < self::MAX_TERMS) {
                $terms[] = $term;
            }
        }

        return new ParsedQuery(terms: $terms, phrases: $phrases, scopes: $scopes, raw: $raw);
    }

    /**
     * Split into quoted phrases and bare tokens.
     *
     * 🛑 An **unterminated** quote is not an error: the rest of the string
     * becomes the phrase. `"access token` searches for the phrase
     * `access token`, which is almost certainly what the reader meant and is
     * the only reading that cannot produce an error message for a half-typed
     * query — a search box sends a keystroke at a time (§8.15.8), so every
     * phrase is unterminated while it is being typed.
     *
     * @return list<array{0: bool, 1: string}>
     */
    private function split(string $query): array
    {
        $out = [];
        $length = strlen($query);
        $cursor = 0;

        while ($cursor < $length) {
            $quote = strpos($query, '"', $cursor);

            if ($quote === false) {
                foreach ($this->words(substr($query, $cursor)) as $word) {
                    $out[] = [false, $word];
                }

                break;
            }

            foreach ($this->words(substr($query, $cursor, $quote - $cursor)) as $word) {
                $out[] = [false, $word];
            }

            $close = strpos($query, '"', $quote + 1);

            if ($close === false) {
                $out[] = [true, substr($query, $quote + 1)];

                break;
            }

            $out[] = [true, substr($query, $quote + 1, $close - $quote - 1)];
            $cursor = $close + 1;
        }

        return $out;
    }

    /**
     * Whitespace-separated words.
     *
     * @return list<string>
     */
    private function words(string $text): array
    {
        $words = preg_split('/\s+/u', trim($text));

        if (! is_array($words)) {
            return [];
        }

        return array_values(array_filter($words, static fn (string $w): bool => $w !== ''));
    }

    /**
     * A scope prefix in a bare token, or null if it is an ordinary term.
     *
     * 🛑 Only the three prefixes §8.16.12 names, matched case-insensitively at
     * the **start** of a token. `see:also` is a term, because `see` is not one
     * of the three — which matters, because documentation is full of
     * colon-bearing words (`http:`, `note:`, `TODO:`) and treating every one as
     * a filter would make them unsearchable.
     */
    private function scopeIn(string $token): ?ScopeRequest
    {
        $colon = strpos($token, ':');

        if ($colon === false || $colon === 0) {
            return null;
        }

        $kind = ScopeKind::tryFrom(strtolower(substr($token, 0, $colon)));

        if (! $kind instanceof ScopeKind) {
            return null;
        }

        $value = substr($token, $colon + 1);

        if ($kind === ScopeKind::Accessible) {
            /*
             * §8.16.12 spells this one filter with a fixed operand: `self:me`.
             * Anything else after `self:` is a typo, and a typo that silently
             * became "the reader's whole accessible set" would widen the search
             * the reader asked to narrow.
             */
            return strtolower($value) === 'me'
                ? new ScopeRequest(ScopeKind::Accessible, '')
                : null;
        }

        if ($kind === ScopeKind::Project) {
            $slash = strpos($value, '/');

            if ($slash !== false) {
                $slug = $this->slug(substr($value, 0, $slash));
                $version = $this->slug(substr($value, $slash + 1));

                return $slug === '' ? null : new ScopeRequest($kind, $slug, $version === '' ? null : $version);
            }
        }

        $slug = $this->slug($value);

        return $slug === '' ? null : new ScopeRequest($kind, $slug);
    }

    /**
     * 🛑 A slug, reduced to the character set §7.2 permits in one.
     *
     * Not a validation — an unknown slug is a legitimate outcome and
     * {@see AuthorisedScope} resolves it against the authorised view. This is
     * a **narrowing**: whatever arrives, what leaves is `[a-z0-9._-]`, so a
     * slug can carry no quote, no bracket, no comma and no space into any
     * driver's filter syntax even if a future driver forgets to escape one.
     *
     * Defence in depth and said plainly: the drivers escape too, and this is
     * the layer that holds if one of them stops.
     */
    private function slug(string $value): string
    {
        $value = strtolower(trim($value));
        $value = (string) preg_replace('/[^a-z0-9._-]+/', '', $value);

        return substr($value, 0, 80);
    }

    /** Collapse whitespace and cap the length of one token. */
    private function normalise(string $token): string
    {
        $token = trim((string) preg_replace('/\s+/u', ' ', $token));

        return mb_substr($token, 0, self::MAX_TERM_LENGTH);
    }
}
