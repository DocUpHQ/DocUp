<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Redirects;

/**
 * 🛑 §8.11.3's save-time half.
 *
 * > "Loops MUST be prevented by save-time cycle detection over the literal
 * > rule graph **and** a runtime hop cap before 404."
 *
 * **"Literal" is the word that defines what this class can and cannot do**,
 * and saying so is more useful than pretending otherwise. A rule set is not
 * a graph: a `prefix` rule relates infinitely many paths, and a `regex` rule
 * relates a set nobody can enumerate. What *is* a graph is the rules'
 * written patterns and targets, and a cycle there — `/a` → `/b`, `/b` → `/a`
 * — is a mistake somebody made in a form, is the common case, and is
 * catchable before it ever reaches a reader.
 *
 * What this misses, the runtime hop cap catches. The two are not redundant;
 * they cover different halves, and §8.11.3 asks for both because either
 * alone leaves a hole: without this, an operator learns about their loop
 * from a reader; without the cap, a `prefix` rule pointing under itself
 * loops forever.
 *
 * 🛑 So the one thing this class must never do is report "no cycle" as "this
 * rule set is safe". It reports what it can see.
 */
final class CycleDetector
{
    /**
     * The cycle a new or edited rule would complete, or null.
     *
     * @param  list<array{from: string, to: string}>  $existing  the literal edges already saved
     * @param  array{from: string, to: string}  $candidate
     * @return list<string>|null the path of the cycle, for the error message
     */
    public static function cycleFor(array $existing, array $candidate): ?array
    {
        /** @var array<string, string> $edges */
        $edges = [];

        foreach ([...$existing, $candidate] as $edge) {
            /*
             * 🛑 First writer wins, which mirrors the engine: rules are
             * evaluated in position order and the first match ends the
             * pass, so a second edge from the same path is unreachable.
             * Letting it overwrite here would make the detector reason
             * about a graph the engine will never walk.
             */
            $from = self::normalise($edge['from']);
            $to = self::normalise($edge['to']);

            if ($from === '' || $to === '' || isset($edges[$from])) {
                continue;
            }

            $edges[$from] = $to;
        }

        $start = self::normalise($candidate['from']);

        if ($start === '' || ! isset($edges[$start])) {
            return null;
        }

        $path = [$start];
        $seen = [$start => true];
        $at = $start;

        /*
         * Walk forward from the candidate rather than searching the whole
         * graph. A cycle that does not pass through the rule being saved
         * was already there and was already refused when it was created;
         * walking from here is linear and reports the cycle the operator
         * is about to create, which is the one they can act on.
         */
        while (isset($edges[$at])) {
            $at = $edges[$at];
            $path[] = $at;

            if (isset($seen[$at])) {
                return $path;
            }

            $seen[$at] = true;
        }

        return null;
    }

    /**
     * A path as the graph compares it.
     *
     * 🛑 Only literal targets are nodes. A target carrying `:splat` or a
     * `$1` back-reference is not a path — it is a template — and treating
     * the template text as a node would produce confident nonsense: `/b/$1`
     * and `/b/$1` from two unrelated rules would look like the same place.
     * Those edges are dropped, and the hop cap is what covers them.
     *
     * An absolute target is likewise not a node here: it leaves the origin,
     * so this project's rules will never be applied to it again.
     */
    private static function normalise(string $value): string
    {
        if (str_contains($value, ':splat') || preg_match('/\$\d/', $value) === 1) {
            return '';
        }

        if (RedirectTarget::isAbsolute($value)) {
            return '';
        }

        $at = strpos($value, '?');
        $path = $at === false ? $value : substr($value, 0, $at);

        return $path === '/' ? '/' : rtrim($path, '/');
    }
}
