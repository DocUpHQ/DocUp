<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

use App\Serving\CachePolicy;

/**
 * 🛑 §8.14.1's four-level cascade, with per-path locking.
 *
 * > "cascading installation → organisation → project → domain mount, with
 * > per-path locking at any level"
 *
 * ## One function, and why it is not a chain of overrides
 *
 * The cascade is a single left fold over the levels in order. Each level
 * contributes the tokens it set and the locks it declared; a level's value wins
 * over everything shallower unless a shallower level locked that token.
 *
 * Written as a fold rather than as a sequence of `??` fallbacks for the reason
 * {@see CachePolicy} gives about its own three-way check: an
 * override chain's failure mode is that somebody adds an input at the wrong end
 * and the last writer wins by accident. Here the ordering is
 * {@see CascadeLevel::inOrder()} and there is one place it is read.
 *
 * ## 🛑 Locks are applied *as the fold proceeds*, not afterwards
 *
 * The lock set accumulated so far is consulted before a level's value is
 * accepted, so a lock declared at organisation level blocks a project value
 * **and** a mount value, and a lock declared at project level blocks only the
 * mount. Applying locks after the fold would need to know which level each
 * surviving value came from — which is exactly the provenance this builds, so
 * it would work, and it would be the second implementation of the same rule.
 *
 * A locked value is **dropped silently here** and refused loudly at write time
 * ({@see ThemeLocks} says why both are needed): resolution runs on every
 * request and cannot throw because an organisation tightened a lock.
 *
 * ## 🛑 The version overlay is not a fifth rung
 *
 * §8.14.1: "Version scope is limited to colour-scheme default and a banner."
 * {@see CascadeLevel::Version} is a {@see ThemeLayer} like any other, and what
 * confines it is {@see BrandingToken::$deepest} on three tokens — so the
 * restriction is registry data that the documentation table prints, not a
 * branch in this class. A version layer carrying `color.brand.primary` would
 * have been refused by {@see TokenGrammar} before it got here, and
 * {@see self::resolve()} drops it again if it somehow did not.
 */
final class ThemeCascade
{
    /**
     * Resolve the layers to one token set.
     *
     * @param  list<ThemeLayer>  $layers  in any order; sorted here
     */
    public static function resolve(array $layers): ResolvedTheme
    {
        usort($layers, static fn (ThemeLayer $a, ThemeLayer $b): int => $a->level->ordinal() <=> $b->level->ordinal());

        $tokens = [];
        $provenance = [];
        $locked = ThemeLocks::none();
        $revisions = [];

        foreach ($layers as $layer) {
            foreach ($layer->tokens as $name => $pair) {
                /*
                 * 🛑 The lock set from *shallower* levels, which is what
                 * `$locked` holds at this point in the fold. A level's own
                 * locks are merged in after its values, so a level can lock a
                 * token and set it in the same revision — which is the normal
                 * case: "this is the brand colour and nobody below changes it".
                 */
                if ($locked->locks($name)) {
                    continue;
                }

                /*
                 * Depth is re-checked on read. The grammar refuses an
                 * out-of-scope write, so this can only fire for a row that
                 * predates a release which narrowed a token's depth — and the
                 * alternative is serving a mount-level override of a token
                 * §8.14.1 says only a version may carry.
                 */
                if (! TokenRegistry::has($name) || ! TokenRegistry::get($name)->settableAt($layer->level)) {
                    continue;
                }

                $tokens[$name] = $pair;
                $provenance[$name] = $layer->level;
            }

            $locked = $locked->merge($layer->locks);

            if ($layer->revisionId !== null) {
                $revisions[$layer->level->value] = $layer->revisionId;
            }
        }

        return new ResolvedTheme($tokens, $provenance, $locked, $revisions);
    }

    /**
     * 🛑 The write-time half: refuse a value a shallower level has locked.
     *
     * @param  array<string, TokenPair>  $tokens  the values being written
     * @param  ThemeLocks  $inherited  the union of every shallower level's locks
     *
     * @throws TokenRefused
     */
    public static function assertWritable(array $tokens, ThemeLocks $inherited, CascadeLevel $level): void
    {
        foreach (array_keys($tokens) as $name) {
            if ($inherited->locks($name)) {
                throw TokenRefused::of(
                    TokenRejection::PathLocked,
                    (string) $name,
                    sprintf('locked above %s scope; ask the owner of that scope to unlock it', $level->value),
                );
            }
        }
    }
}
