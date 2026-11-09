<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

/**
 * 🛑 §8.14.1's "per-path locking at any level".
 *
 * A level may lock a token path, and no level below it may then set that token.
 * The use that justifies it is concrete: an organisation that has signed a
 * brand guideline locks `color.brand.primary` and `asset.logo`, and its two
 * hundred project owners keep every other token. An installation that white
 * labels for a regulator locks the lot.
 *
 * ## 🛑 Locks are enforced twice, and the second time is the one that matters
 *
 * At **write** time, a deeper level that tries to set a locked token is
 * refused with {@see TokenRejection::PathLocked}. That is the useful error.
 *
 * At **resolution** time, {@see ThemeCascade} *also* drops a deeper value whose
 * token a shallower level locks — even though the write should have refused it.
 * Without that, a lock applied after the fact would have no effect on values
 * already stored, so locking a token would require finding and deleting every
 * deeper override. An organisation would lock its logo and two hundred
 * projects would carry on serving their own, with the dashboard showing a lock.
 *
 * ## Why a list of exact names rather than a prefix grammar
 *
 * `color.*` reads well and is a second grammar to keep right, and a prefix
 * silently acquires tokens: a release that adds `color.brand.tertiary` would
 * extend every existing `color.brand.*` lock to cover a token the operator who
 * wrote the lock never saw. Exact names mean a lock covers what it says.
 * {@see self::expand()} is the one convenience — a **group** name, from the
 * registry, resolved to its members at write time and stored expanded, so the
 * stored lock is still exact.
 */
final readonly class ThemeLocks
{
    /** How many paths one level may lock. The registry has 45; locking all of them is 45 entries. */
    private const MAX_PATHS = 64;

    /**
     * @param  list<string>  $paths  exact token names, sorted
     */
    private function __construct(public array $paths) {}

    public static function none(): self
    {
        return new self([]);
    }

    /**
     * Build from an authored list of token names or registry group names.
     *
     * @param  array<array-key, mixed>  $authored
     *
     * @throws TokenRefused
     */
    public static function fromAuthored(array $authored): self
    {
        if (count($authored) > self::MAX_PATHS) {
            throw TokenRefused::of(
                TokenRejection::TooManyEntries,
                'locks',
                sprintf('%d paths; the limit is %d', count($authored), self::MAX_PATHS),
            );
        }

        $paths = [];

        foreach ($authored as $entry) {
            if (! is_string($entry)) {
                throw TokenRefused::of(TokenRejection::UnknownLockPath, 'locks', 'a lock path is a string');
            }

            foreach (self::expand($entry) as $path) {
                $paths[$path] = true;
            }
        }

        $names = array_keys($paths);
        sort($names);

        return new self($names);
    }

    /**
     * Rebuild from storage.
     *
     * 🛑 An unknown path is **dropped** rather than refused, which is the one
     * place this class is lenient and the only place it can afford to be. A
     * stored lock naming a token a later release removed would otherwise make
     * every theme in the installation unresolvable — the cascade would throw on
     * read, and an operator could not even open the page to fix it. Dropping it
     * loses a lock on a token that no longer exists, which protects nothing.
     *
     * @param  array<array-key, mixed>  $stored
     */
    public static function fromStorage(array $stored): self
    {
        $paths = [];

        foreach ($stored as $entry) {
            if (is_string($entry) && TokenRegistry::has($entry)) {
                $paths[] = $entry;
            }
        }

        sort($paths);

        return new self(array_values(array_unique($paths)));
    }

    public function locks(string $token): bool
    {
        return in_array($token, $this->paths, true);
    }

    public function isEmpty(): bool
    {
        return $this->paths === [];
    }

    /** The union of this set and another — how locks accumulate down the cascade. */
    public function merge(self $other): self
    {
        $paths = array_values(array_unique([...$this->paths, ...$other->paths]));
        sort($paths);

        return new self($paths);
    }

    /** @return list<string> */
    public function toStorage(): array
    {
        return $this->paths;
    }

    /**
     * One authored entry to the token names it locks.
     *
     * A registry token name locks itself. A registry **group** name locks every
     * token in that group, expanded now so the stored lock is a list of exact
     * names and a later release that adds a token to the group does not widen a
     * lock somebody already reviewed.
     *
     * @return list<string>
     *
     * @throws TokenRefused
     */
    private static function expand(string $entry): array
    {
        if (TokenRegistry::has($entry)) {
            return [$entry];
        }

        $group = TokenRegistry::group($entry);

        if ($group !== []) {
            return array_map(static fn (BrandingToken $token): string => $token->name, $group);
        }

        throw TokenRefused::of(
            TokenRejection::UnknownLockPath,
            'locks',
            sprintf('%s is neither a token nor a token group', $entry),
        );
    }
}
