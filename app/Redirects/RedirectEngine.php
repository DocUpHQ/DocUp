<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Redirects;

/**
 * §8.11.2's six rule types, evaluated; §8.11.3's hop cap, enforced;
 * §8.11.4's evaluation cap, counted.
 *
 * 🛑 **Pure.** No database, no cache, no clock, no configuration read at
 * match time — a {@see RedirectSet} in, a {@see RedirectMatch} or null out.
 * The reason is §8.11.4's "a **fixed deterministic** per-request evaluation
 * cap": determinism is a property of a function, and the way to have it is
 * for the matching to *be* one. It is also what makes the twelve-case table
 * of §17's exit criterion assertable as a table rather than as twelve
 * integration tests.
 */
final readonly class RedirectEngine
{
    /**
     * 🛑 §8.11.3's runtime hop cap.
     *
     * Save-time cycle detection covers the literal rule graph, and that is
     * not everything: a `prefix` rule whose target falls under its own
     * pattern, or two `regex` rules whose outputs feed each other, make a
     * loop no graph over literals can see. Four is generous — a chain
     * longer than that is a rule set nobody understands — and the
     * requirement is that it 404s rather than looping.
     */
    public const int MAX_HOPS = 4;

    /**
     * Follow the rules from one path, up to the hop cap.
     *
     * @param  string  $path  the request path, canonical and root-relative
     * @param  string  $language  the language segment the request carried, for
     *                            `version_agnostic` rules; empty when there is none
     * @param  string  $version  likewise the version segment
     * @param  bool  $forced  which of §8.11.1's two passes this is
     * @return RedirectMatch|null null when nothing matched, **and** when the
     *                            hop cap was reached — the caller 404s either
     *                            way, which is what §8.11.3 asks for
     */
    public function follow(
        RedirectSet $set,
        string $path,
        string $language = '',
        string $version = '',
        bool $forced = false,
    ): ?RedirectMatch {
        if ($set->isEmpty()) {
            return null;
        }

        $rules = $set->pass($forced);

        if ($rules === []) {
            return null;
        }

        $current = $path;
        $seen = [$path => true];
        $budget = RegexGuard::MAX_EVALUATIONS_PER_REQUEST;
        $settled = null;

        for ($hop = 1; $hop <= self::MAX_HOPS; $hop++) {
            $match = $this->once($rules, $current, $language, $version, $budget, $set->regexEnabled);

            if ($match === null) {
                /*
                 * Nothing matched. Whatever the last move was is the
                 * answer — or there was no move at all, and there is no
                 * redirect.
                 */
                return $settled;
            }

            [$target, $status, $rule] = $match;

            /*
             * 🛑 A cross-origin target ends the chain immediately. There is
             * nothing to follow — the next request goes to somebody else's
             * server — and matching our own rules against a path on another
             * host would be applying this project's rules to a URL that is
             * not ours.
             */
            if (RedirectTarget::isAbsolute($target)) {
                return RedirectMatch::to($target, $status, $rule, $hop);
            }

            /*
             * 🛑 A revisited path is a loop the literal graph could not
             * see — §8.11.3's second half. Answering null makes the caller
             * 404, which is the requirement: "a runtime chain exceeding the
             * hop cap 404s", and a cycle is a chain that never ends.
             */
            if (isset($seen[$target])) {
                return null;
            }

            $seen[$target] = true;
            $current = $target;
            $settled = RedirectMatch::to($target, $status, $rule, $hop);
        }

        /*
         * The cap was reached with a rule still matching, which means the
         * chain is longer than anybody intended. 404, deliberately, rather
         * than serving the fifth hop: a chain this long is a rule set with
         * a mistake in it, and following it would hide the mistake.
         */
        return null;
    }

    /**
     * One pass over the rules, in position order, first match wins.
     *
     * @param  list<array{id: string, position: int, kind: string, forced: bool, from: string, to: string, status: int}>  $rules
     * @param  int  $budget  §8.11.4's evaluation cap, decremented by regex rules only
     * @param  bool  $regexEnabled  §8.11.4's kill switch, **as the set was
     *                              built**, not as configuration reads now
     * @return array{0: string, 1: int, 2: string}|null
     */
    private function once(
        array $rules,
        string $path,
        string $language,
        string $version,
        int &$budget,
        bool $regexEnabled,
    ): ?array {
        foreach ($rules as $rule) {
            $kind = RedirectKind::tryFrom($rule['kind']);

            if ($kind === null) {
                continue;
            }

            /*
             * 🛑 Only regex rules spend the budget, and that is the point
             * of the cap being on evaluations rather than on rules. An
             * `exact` match is a string comparison; a thousand of them cost
             * less than one pathological regex. Counting them together
             * would make the cap bite on the cheap rules and leave the
             * expensive ones uncapped.
             */
            if ($kind === RedirectKind::Regex) {
                /*
                 * 🛑 The switch is read from the **set**, not from
                 * configuration, and that is what keeps this class pure.
                 * §8.11.4 asks for "a **fixed deterministic**
                 * per-request evaluation cap", and an earlier draft of
                 * this method called `RegexGuard::enabled()` here — which
                 * reads `config()`, which makes the engine depend on a
                 * container and makes two calls with the same arguments
                 * able to disagree. The set is built once per request from
                 * configuration; the matching is a function of the set.
                 */
                if ($budget <= 0 || ! $regexEnabled) {
                    continue;
                }

                $budget--;
            }

            $target = $this->apply($kind, $rule, $path, $language, $version);

            if ($target !== null) {
                return [$target, $rule['status'], $rule['kind'].'#'.$rule['position']];
            }
        }

        return null;
    }

    /**
     * @param  array{id: string, position: int, kind: string, forced: bool, from: string, to: string, status: int}  $rule
     */
    private function apply(RedirectKind $kind, array $rule, string $path, string $language, string $version): ?string
    {
        return match ($kind) {
            RedirectKind::Exact => $path === $rule['from'] ? $rule['to'] : null,
            RedirectKind::Prefix => $this->prefix($rule['from'], $rule['to'], $path),
            RedirectKind::VersionAgnostic => $this->versionAgnostic($rule['from'], $rule['to'], $path, $language, $version),
            RedirectKind::CleanUrl => $this->cleanUrl($rule['from'], $path),
            RedirectKind::HtmlExtension => $this->htmlExtension($rule['from'], $path),
            RedirectKind::Regex => $this->regex($rule['from'], $rule['to'], $path),
        };
    }

    /**
     * `/guide/:splat` → `/handbook/:splat`.
     *
     * 🛑 The pattern's `:splat` is stripped to a prefix and the remainder
     * is substituted into the target. `/guide/` with an empty remainder
     * matches, because a section that moved moved its index page too.
     */
    private function prefix(string $from, string $to, string $path): ?string
    {
        $prefix = str_ends_with($from, ':splat') ? substr($from, 0, -6) : $from;

        if (! str_starts_with($path, $prefix)) {
            return null;
        }

        return str_replace(':splat', substr($path, strlen($prefix)), $to);
    }

    /**
     * A page that moved in every version.
     *
     * 🛑 The pattern is written **without** `{lang}/{version}` and the
     * engine supplies what the request carried, so one rule covers every
     * version that exists and every version that will. A request with no
     * version segment has nothing to re-attach and is left alone, rather
     * than being redirected to a path missing its prefix.
     */
    private function versionAgnostic(string $from, string $to, string $path, string $language, string $version): ?string
    {
        if ($language === '' || $version === '') {
            return null;
        }

        $prefix = '/'.$language.'/'.$version;

        if (! str_starts_with($path, $prefix.'/') && $path !== $prefix) {
            return null;
        }

        $within = substr($path, strlen($prefix));
        $within = $within === '' ? '/' : $within;

        if ($within !== $from) {
            return null;
        }

        return $prefix.$to;
    }

    /**
     * `/a/b.html` → `/a/b/`, under a scope.
     *
     * 🛑 `index.html` is the exception and it is not an edge case: under
     * directory URLs the index of a directory **is** the directory, so
     * `/a/index.html` becomes `/a/` rather than `/a/index/`. Getting this
     * wrong produces a rule that sends every section index to a path that
     * does not exist.
     */
    private function cleanUrl(string $scope, string $path): ?string
    {
        if (! str_starts_with($path, $scope) || ! str_ends_with($path, '.html')) {
            return null;
        }

        $stem = substr($path, 0, -5);

        if (str_ends_with($stem, '/index')) {
            return substr($stem, 0, -5);
        }

        return $stem.'/';
    }

    /** The reverse: `/a/b/` → `/a/b.html`, and `/a/` → `/a/index.html`. */
    private function htmlExtension(string $scope, string $path): ?string
    {
        if (! str_starts_with($path, $scope) || ! str_ends_with($path, '/')) {
            return null;
        }

        $stem = rtrim($path, '/');

        return $stem === '' ? '/index.html' : $stem.'.html';
    }

    /**
     * A PCRE rule, with `$1`-style back-references in the target.
     *
     * The guard has already refused anything that should not run; what is
     * left here is substitution. `preg_replace` is deliberately **not**
     * used: it would re-interpret the target as a replacement expression
     * including `\0` and `$0`, and a target is operator-supplied text that
     * happens to contain a dollar sign more often than anyone expects.
     */
    private function regex(string $pattern, string $target, string $path): ?string
    {
        $captures = RegexGuard::match($pattern, $path);

        if ($captures === null) {
            return null;
        }

        $result = $target;

        /*
         * Highest index first, so `$10` is not eaten by `$1` followed by a
         * literal zero. The same bug in the other direction is why
         * `str_replace` with an array is not used either: it applies its
         * pairs in order and would do exactly that.
         */
        for ($i = count($captures) - 1; $i >= 0; $i--) {
            $result = str_replace('$'.$i, $captures[$i], $result);
        }

        return $result;
    }
}
