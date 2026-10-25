<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

/**
 * Enough of semantic versioning for §8.7.5's three label-ordering selectors.
 *
 * `track_semver_range`, `latest_release` and `mirror_label`'s
 * `newest_semver_lte` all need the same two operations: parse a version
 * label, and order two of them. This provides exactly those, and a range
 * grammar narrow enough to be read in one sitting.
 *
 * 🛑 **Written rather than taken from a library, and the reason is the
 * input.** The labels here come from git tags in repositories DocUp does not
 * control — `v2.1`, `2.1.0-rc.1`, `release-2`, `main`. A library that throws
 * on an unparseable version would make an ordinary branch name an exception
 * on the publish path; this returns null instead, and every caller treats an
 * unparseable label as "not comparable" rather than as zero. A label that
 * sorts as 0.0.0 is how `main` wins a `newest_semver_lte` race it should not
 * have entered.
 *
 * Deliberately **not** supported: build metadata ordering (`+build` is
 * ignored for comparison, as SemVer 2.0.0 requires), hyphen ranges, and `x`
 * wildcards outside the leading position. Each would be a line of grammar
 * nobody in this product writes.
 */
final readonly class SemanticVersion
{
    /**
     * @param  list<string>  $prerelease  dot-separated identifiers, empty for a stable release
     */
    private function __construct(
        public int $major,
        public int $minor,
        public int $patch,
        public array $prerelease,
    ) {}

    /**
     * Parse a version label, or null when it is not one.
     *
     * Accepts a leading `v` because the overwhelming majority of git tags
     * carry one, and accepts a partial version — `2`, `2.1` — because a tag
     * named `v2` is common and refusing it would make `latest_release`
     * silently skip a real release.
     */
    public static function parse(string $label): ?self
    {
        $candidate = ltrim(trim($label), 'vV');

        if ($candidate === '') {
            return null;
        }

        /*
         * 🛑 A prerelease is accepted only after at least `MAJOR.MINOR`.
         *
         * SemVer 2.0.0 requires all three numbers; this parser is lenient
         * about the last two because `v2` and `v2.1` are ordinary git tags
         * and refusing them would make `latest_release` skip real
         * releases. Extending that leniency to the prerelease part is a
         * step too far: `2026-03-04` would otherwise parse as
         * `2026.0.0-03.04`, and a date tag silently entering a version
         * ordering is exactly the quiet wrong answer this class exists to
         * avoid.
         */
        $matched = preg_match(
            '/^(\d+)(?:\.(\d+)(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?)?(?:\+[0-9A-Za-z.-]+)?$/',
            $candidate,
            $parts,
        );

        if ($matched !== 1) {
            return null;
        }

        $prerelease = ($parts[4] ?? '') === '' ? [] : explode('.', $parts[4]);

        return new self(
            (int) $parts[1],
            (int) ($parts[2] ?? '0'),
            (int) ($parts[3] ?? '0'),
            $prerelease,
        );
    }

    /** Whether this is a stable release, i.e. carries no prerelease part. */
    public function isStable(): bool
    {
        return $this->prerelease === [];
    }

    /**
     * SemVer 2.0.0 precedence: -1, 0 or 1.
     *
     * 🛑 A prerelease sorts **below** its own release — `2.0.0-rc.1` is less
     * than `2.0.0` — which is the rule that makes `latest_release` able to
     * exclude prereleases and `newest_semver_lte` able to include them
     * without a release candidate shadowing the release it preceded.
     */
    public function compare(self $other): int
    {
        $ordering = $this->major <=> $other->major
            ?: $this->minor <=> $other->minor
            ?: $this->patch <=> $other->patch;

        if ($ordering !== 0) {
            return $ordering;
        }

        if ($this->prerelease === [] && $other->prerelease === []) {
            return 0;
        }

        // A version WITHOUT a prerelease part outranks one with it.
        if ($this->prerelease === []) {
            return 1;
        }

        if ($other->prerelease === []) {
            return -1;
        }

        return $this->comparePrerelease($other->prerelease);
    }

    /**
     * Whether this version satisfies a range expression.
     *
     * The grammar, in full:
     *
     * ```
     * range      → conjunction ( '||' conjunction )*
     * conjunction→ comparator ( ' ' comparator )*
     * comparator → ( '^' | '~' | '>=' | '<=' | '>' | '<' | '=' )? version
     * ```
     *
     * An unparseable comparator makes the whole range refuse rather than
     * match: a typo in a range must not quietly widen it, because the result
     * is a project serving a contributing repository's unreleased work.
     */
    public function satisfies(string $range): bool
    {
        foreach (explode('||', $range) as $conjunction) {
            if ($this->satisfiesConjunction(trim($conjunction))) {
                return true;
            }
        }

        return false;
    }

    public function __toString(): string
    {
        $base = $this->major.'.'.$this->minor.'.'.$this->patch;

        return $this->prerelease === [] ? $base : $base.'-'.implode('.', $this->prerelease);
    }

    private function satisfiesConjunction(string $conjunction): bool
    {
        $comparators = preg_split('/\s+/', trim($conjunction)) ?: [];
        $any = false;

        foreach ($comparators as $comparator) {
            if ($comparator === '') {
                continue;
            }

            $any = true;

            if (! $this->satisfiesComparator($comparator)) {
                return false;
            }
        }

        return $any;
    }

    private function satisfiesComparator(string $comparator): bool
    {
        $matched = preg_match('/^(\^|~|>=|<=|>|<|=)?\s*(.+)$/', $comparator, $parts);

        if ($matched !== 1) {
            return false;
        }

        $operator = $parts[1] === '' ? '=' : $parts[1];
        $bound = self::parse($parts[2]);

        if (! $bound instanceof self) {
            return false;
        }

        return match ($operator) {
            '=' => $this->compare($bound) === 0,
            '>' => $this->compare($bound) > 0,
            '>=' => $this->compare($bound) >= 0,
            '<' => $this->compare($bound) < 0,
            '<=' => $this->compare($bound) <= 0,
            '^' => $this->withinCaret($bound),

            // The only operator left: the pattern above admits no others.
            default => $this->withinTilde($bound),
        };
    }

    /**
     * `^2.1.0` is `>=2.1.0 <3.0.0`; `^0.2.1` is `>=0.2.1 <0.3.0`.
     *
     * The zero-major special case is npm's and is the one everybody forgets.
     * Under `0.x` the minor is the breaking-change axis, so a caret range
     * that ignored it would pull in a breaking release under a constraint
     * written to avoid exactly that.
     */
    private function withinCaret(self $bound): bool
    {
        if ($this->compare($bound) < 0) {
            return false;
        }

        if ($bound->major > 0) {
            return $this->major === $bound->major;
        }

        if ($bound->minor > 0) {
            return $this->major === 0 && $this->minor === $bound->minor;
        }

        return $this->major === 0 && $this->minor === 0 && $this->patch === $bound->patch;
    }

    /** `~2.1.0` is `>=2.1.0 <2.2.0`. */
    private function withinTilde(self $bound): bool
    {
        if ($this->compare($bound) < 0) {
            return false;
        }

        return $this->major === $bound->major && $this->minor === $bound->minor;
    }

    /**
     * @param  list<string>  $other
     */
    private function comparePrerelease(array $other): int
    {
        $count = max(count($this->prerelease), count($other));

        for ($index = 0; $index < $count; $index++) {
            $mine = $this->prerelease[$index] ?? null;
            $theirs = $other[$index] ?? null;

            // A shorter set of identifiers sorts lower when all preceding
            // ones are equal: `1.0.0-alpha` < `1.0.0-alpha.1`.
            if ($mine === null) {
                return -1;
            }

            if ($theirs === null) {
                return 1;
            }

            $mineNumeric = ctype_digit($mine);
            $theirsNumeric = ctype_digit($theirs);

            if ($mineNumeric && $theirsNumeric) {
                $ordering = (int) $mine <=> (int) $theirs;
            } elseif ($mineNumeric) {
                // Numeric identifiers always have lower precedence.
                $ordering = -1;
            } elseif ($theirsNumeric) {
                $ordering = 1;
            } else {
                $ordering = strcmp($mine, $theirs) <=> 0;
            }

            if ($ordering !== 0) {
                return $ordering;
            }
        }

        return 0;
    }
}
