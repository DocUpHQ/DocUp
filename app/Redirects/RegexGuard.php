<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Redirects;

/**
 * 🛑 §8.11.4's containment for regular-expression rules.
 *
 * > "Regular-expression rules MUST be contained by a length cap (255), a
 * > nested-quantifier linter, a compile check, a lowered PCRE backtrack
 * > limit, a **fixed deterministic per-request evaluation cap** (20) and an
 * > installation-wide kill switch. A time-budget cap that silently skips
 * > rules under load makes redirect behaviour nondeterministic, which is
 * > worse than a fixed cap."
 *
 * **Six controls, and the last sentence is the design.** The obvious
 * containment for a regex is a time budget: evaluate until the clock runs
 * out, then stop. It is also the wrong one, and the requirement says why — a
 * rule that fires on a quiet morning and does not fire under load is a rule
 * whose behaviour depends on the weather. A reader gets a 404 and an
 * operator cannot reproduce it. A fixed count of 20 is worse for the
 * operator who wanted 21 rules and better for everybody, because it is the
 * same on every request on every replica.
 *
 * The six, and what each one closes:
 *
 * | Control | What it closes |
 * |---|---|
 * | 255-byte cap | the pattern nobody can read, and most of the pathological space |
 * | nested-quantifier linter | `(a+)+` — the catastrophic class, before it runs |
 * | compile check | a pattern that would throw at request time |
 * | lowered backtrack limit | what the linter did not recognise |
 * | fixed evaluation cap (20) | a project with 500 regex rules |
 * | kill switch | the installation that would rather have none |
 *
 * 🛑 No single one of them is sufficient and the linter least of all:
 * recognising catastrophic backtracking in general is undecidable, so the
 * linter catches the shapes people actually write and the backtrack limit
 * catches the rest by refusing to spend more than a bounded number of steps.
 */
final class RegexGuard
{
    /** §8.11.4's own number. */
    public const int MAX_PATTERN_BYTES = 255;

    /** §8.11.4's own number: a fixed count, never a clock. */
    public const int MAX_EVALUATIONS_PER_REQUEST = 20;

    /**
     * PCRE steps per match, well below the 1,000,000 default.
     *
     * 🛑 Set per match via the `(*LIMIT_MATCH=…)` verb rather than by
     * writing `pcre.backtrack_limit` at runtime. An `ini_set` is
     * process-wide: it would lower the limit for every other `preg_*` call
     * in the request — the path validator, the configuration parser, the
     * log scrubber — and any of those exceeding it fails **silently**,
     * because `preg_match` returns false rather than throwing. A verb
     * inside the pattern applies to that pattern and nothing else.
     */
    public const int BACKTRACK_LIMIT = 10_000;

    /**
     * Whether regular-expression rules may run at all (§8.11.4's kill switch).
     *
     * 🛑 Defaults **on**, which is the one control here that does not
     * default closed — and deliberately, because §20.4's invariant is about
     * security controls, and this switch is the opposite: turning it off
     * removes a feature rather than a protection. An installation that
     * turns it off is choosing to lose regex rules; one that leaves it on
     * still has the other five controls.
     */
    public static function enabled(): bool
    {
        return config('redirects.regex_enabled') !== false;
    }

    /**
     * Refuse a pattern that must never reach the engine.
     *
     * 🛑 **Pure**: five of §8.11.4's six controls are here and none of them
     * reads configuration. The sixth, the kill switch, is policy rather than
     * containment and lives with the rest of the save-time policy in
     * {@see Redirects}. An earlier draft checked it here, which made this
     * class need a container — and a validator that cannot be called without
     * one is a validator nobody unit-tests.
     *
     * @throws RedirectRefused
     */
    public static function assertUsable(string $pattern): void
    {
        if ($pattern === '') {
            throw RedirectRefused::of(RedirectRejection::PatternMalformed, 'an empty pattern matches everything');
        }

        if (strlen($pattern) > self::MAX_PATTERN_BYTES) {
            throw RedirectRefused::of(
                RedirectRejection::RegexTooLong,
                strlen($pattern).' bytes, over the '.self::MAX_PATTERN_BYTES.'-byte cap',
            );
        }

        $nested = self::nestedQuantifier($pattern);

        if ($nested !== null) {
            throw RedirectRefused::of(
                RedirectRejection::RegexNestedQuantifier,
                $nested.' is a nested quantifier: on a non-matching input it backtracks exponentially',
            );
        }

        if (! self::compiles($pattern)) {
            throw RedirectRefused::of(RedirectRejection::RegexUncompilable, 'PCRE would not compile this pattern');
        }
    }

    /**
     * Match a pattern against a path, bounded.
     *
     * Returns the capture groups, or null for no match **and for a match
     * that exceeded the backtrack limit** — the two are deliberately the
     * same answer at this level, because a rule that cannot be evaluated
     * within the budget has not matched, and treating it as a match would
     * be the nondeterminism §8.11.4 refuses.
     *
     * @return list<string>|null
     */
    public static function match(string $pattern, string $path): ?array
    {
        $matches = [];

        $result = @preg_match(self::delimit($pattern), $path, $matches);

        if ($result !== 1) {
            return null;
        }

        /*
         * `array_values`, because `preg_match` fills named groups under
         * their names as well as their numbers — so a pattern with
         * `(?<slug>…)` produces a map, and the engine substitutes by
         * numeric index.
         */
        return array_values(array_map(strval(...), $matches));
    }

    /**
     * 🛑 The nested-quantifier linter: a quantified group that itself ends
     * in a quantifier.
     *
     * `(a+)+`, `(a*)*`, `(a+)*`, `([a-z]+)+` and `(\w{2,})+` are the shapes
     * that turn a 30-character pattern and a 40-character input into
     * billions of steps. The check is deliberately syntactic and
     * deliberately over-broad: recognising catastrophic backtracking in
     * general is undecidable, so this catches what people write and refuses
     * some patterns that would have been fine. Refusing a safe pattern
     * costs an operator one rewrite; accepting an unsafe one costs the
     * installation its serving path.
     *
     * @return string|null the offending fragment, or null when there is none
     */
    public static function nestedQuantifier(string $pattern): ?string
    {
        /*
         * A group whose contents end in a quantifier, where the group
         * itself is quantified. `\((?:[^()\\]|\\.)*` is the group body
         * without nesting — enough for the shapes above, and a pattern with
         * nested *groups* as well as nested quantifiers is over the length
         * cap long before it is interesting.
         */
        $quantified = '(?:[*+]|\{\d+,\}|\{\d+,\d+\})';

        if (preg_match('/(\((?:[^()\\\\]|\\\\.)*'.$quantified.'\??\)\s*'.$quantified.')/', $pattern, $m) === 1) {
            return $m[1];
        }

        /*
         * The same shape written with a back-reference or an alternation
         * inside: `(a|aa)+` is the other classic, and it has no inner
         * quantifier at all. An alternation whose branches overlap is not
         * decidable syntactically either, so this refuses a quantified
         * group containing an alternation — again over-broad, again the
         * safe direction.
         */
        if (preg_match('/(\((?:[^()\\\\]|\\\\.)*\|(?:[^()\\\\]|\\\\.)*\)\s*'.$quantified.')/', $pattern, $m) === 1) {
            return $m[1];
        }

        return null;
    }

    /**
     * Whether PCRE accepts the pattern at all.
     *
     * 🛑 Behind a real error handler, not `@`. A compile failure here is an
     * **expected outcome** — the whole purpose of the call is to find out —
     * and PHP still raises a warning for it. `@` suppresses the message and
     * not the diagnostic, so under a strict error handler (PHPUnit's, and
     * any installation that converts warnings to exceptions) the probe
     * throws instead of answering. Installing a handler that swallows the
     * one warning this call can produce is the only way to ask the
     * question without the asking being an error.
     */
    public static function compiles(string $pattern): bool
    {
        set_error_handler(static fn (): bool => true);

        try {
            return preg_match(self::delimit($pattern), '') !== false;
        } finally {
            restore_error_handler();
        }
    }

    /**
     * The pattern as PCRE receives it: anchored, bounded and `~`-delimited.
     *
     * 🛑 Anchored at both ends. An unanchored redirect pattern matches a
     * substring, so `/guide` would fire on `/not-the-guide/page` — which is
     * not what any operator writing a redirect means, and is how a rule
     * intended for one section silently captures another.
     *
     * 🛑 `~` as the delimiter, not `/`, because every pattern here is about
     * paths and a path is full of slashes. With `/` the operator would have
     * to escape each one, and the first unescaped slash would end the
     * pattern early and change its meaning rather than fail — which the
     * compile check would then pass.
     */
    public static function delimit(string $pattern): string
    {
        return '~(*LIMIT_MATCH='.self::BACKTRACK_LIMIT.')\A'.str_replace('~', '\~', $pattern).'\z~u';
    }
}
