<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Versions;

/**
 * §8.6.4's per-project version comparator.
 *
 * > "The comparator MUST be configurable per project — `semver` (default),
 * > `pep440`, `calver` or `alphabetical` — and the **same** comparator MUST
 * > drive both this derivation and the §8.6.5 flyout order, so a project
 * > tagging `1.0rc1` or `1.0.post1` cannot get one order in its version list
 * > and another in its `stable` pointer."
 *
 * 🛑 **One comparator, two readers, and that is the requirement rather than
 * a convenience.** `stable` is derived with it and the flyout is ordered with
 * it, so a project whose list says `1.0.post1` is newest and whose `stable`
 * points at `1.0` has a bug nobody can explain from either side alone. Every
 * caller takes the comparator from the project row; nothing sorts versions
 * with `sort()`.
 *
 * 🛑 **`v1.10` above `v1.9` is the first bug report every new installation
 * receives** (§8.6.5), and it is the reason `alphabetical` exists as an
 * *option* rather than as the behaviour. A project whose refs are
 * `2024-06-01` and `2024-06-02` wants string order; a project whose refs are
 * `v1.9` and `v1.10` emphatically does not, and the two cannot be served by
 * guessing.
 */
enum VersionComparator: string
{
    /**
     * Semantic versioning, the default.
     *
     * Implemented against the spec's own precedence rules rather than by
     * `version_compare`: PHP's function treats `1.0.0-rc1` as *newer* than
     * `1.0.0` on some inputs and has its own vocabulary of `dev`, `alpha`,
     * `pl` and `#` that semver does not share. Borrowing it would make the
     * published behaviour "whatever PHP does this decade".
     */
    case Semver = 'semver';

    /** Python's PEP 440: epochs, `rc`, `.post`, `.dev`, local versions. */
    case Pep440 = 'pep440';

    /** Calendar versioning: `2026.10`, `2026.10.24`, `24.04.1`. */
    case Calver = 'calver';

    /** Byte order. For projects whose refs are not versions at all. */
    case Alphabetical = 'alphabetical';

    /** 🛑 The safe read of a stored value, as every enum here does it. */
    public static function fromStored(?string $value): self
    {
        return self::tryFrom((string) $value) ?? self::Semver;
    }

    /**
     * Compare two ref names, newest **last** (so `usort` ascends).
     *
     * @return int negative when `$a` is older, positive when newer, 0 when equal
     */
    public function compare(string $a, string $b): int
    {
        return $this->rank($a, $b) ?: strcmp($a, $b);
    }

    /**
     * The version comparison alone, with no tie-break.
     *
     * 🛑 Separate from {@see compare()} so the tie-break can stay
     * **ascending in both directions**. Were `descending()` simply to call
     * `compare($b, $a)`, two refs naming the same version — `v1.2` and
     * `v1.2.0`, say — would come back reverse-alphabetically there and
     * alphabetically here. Both orders are deterministic; having two of
     * them is what makes a flyout and an API list disagree about refs
     * neither can tell apart.
     *
     * 🛑 A ref the comparator cannot read ranks BELOW every ref it can.
     * Without this a branch called `feature-login` would land in the middle
     * of a release list — and, worse, could win §8.6.4's "highest branch"
     * step and become `stable`.
     */
    private function rank(string $a, string $b): int
    {
        if ($this === self::Alphabetical) {
            return strcmp($a, $b);
        }

        $left = $this->parse($a);
        $right = $this->parse($b);

        if ($left === null || $right === null) {
            if ($left === null && $right === null) {
                return 0;
            }

            return $left === null ? -1 : 1;
        }

        return $this->comparePartsOf($left, $right);
    }

    /**
     * Is this ref a prerelease?
     *
     * 🛑 §8.6.4 excludes prereleases from `stable`: "the highest **tag** by
     * the project's configured comparator, **prereleases excluded**". A
     * project that tags `v2.0.0-rc1` and finds `stable` pointing at it has
     * shipped a release candidate to every reader who did not pick a version.
     */
    public function isPrerelease(string $ref): bool
    {
        $parsed = $this->parse($ref);

        return $parsed !== null && $parsed['pre'] !== [];
    }

    /** Can this comparator read the ref at all? */
    public function understands(string $ref): bool
    {
        return $this === self::Alphabetical || $this->parse($ref) !== null;
    }

    /**
     * Sort ref names newest first.
     *
     * @param  list<string>  $refs
     * @return list<string>
     */
    public function descending(array $refs): array
    {
        // The version comparison is inverted; the tie-break is not. See
        // {@see rank()} for why those are two different decisions.
        usort($refs, fn (string $a, string $b): int => $this->rank($b, $a) ?: strcmp($a, $b));

        return $refs;
    }

    /**
     * The highest of a set, or null when the set is empty.
     *
     * @param  list<string>  $refs
     */
    public function highest(array $refs, bool $excludePrereleases = false): ?string
    {
        $candidates = $excludePrereleases
            ? array_values(array_filter($refs, fn (string $ref): bool => ! $this->isPrerelease($ref)))
            : $refs;

        /*
         * 🛑 A ref the comparator cannot read is not a candidate for
         * `stable`, rather than a candidate that happens to sort low. A
         * project with no parseable tags gets §8.6.4's step 5 — "no `stable`
         * at all, which is a valid state and MUST NOT fall back to the
         * default branch" — and silently picking `feature/login` would be
         * precisely the fall back that sentence forbids.
         */
        $readable = array_values(array_filter($candidates, $this->understands(...)));

        if ($readable === []) {
            return null;
        }

        return $this->descending($readable)[0];
    }

    /**
     * The release and prerelease parts of a ref, or null when unreadable.
     *
     * @return array{release: list<int>, pre: list<array{0: int, 1: int|string}>, epoch: int}|null
     */
    private function parse(string $ref): ?array
    {
        // A single leading `v` is universal across all three schemes and is
        // not part of the version. `V2.0.0` too: tags are typed by hand.
        $text = preg_replace('/^[vV](?=\d)/', '', trim($ref)) ?? $ref;

        return match ($this) {
            self::Semver => $this->parseSemver($text),
            self::Pep440 => $this->parsePep440($text),
            self::Calver => $this->parseCalver($text),
            self::Alphabetical => null,
        };
    }

    /**
     * semver.org 2.0.0: `MAJOR.MINOR.PATCH[-prerelease][+build]`.
     *
     * 🛑 The patch component is optional here where semver requires it,
     * because real repositories tag `v1.9` and `v2` constantly and a
     * comparator that refused them would push every such project to
     * `alphabetical` — which is the setting that produces the bug §8.6.5
     * names. Build metadata is parsed and discarded, as semver requires.
     *
     * @return array{release: list<int>, pre: list<array{0: int, 1: int|string}>, epoch: int}|null
     */
    private function parseSemver(string $text): ?array
    {
        if (preg_match('/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/', $text, $m) !== 1) {
            return null;
        }

        return [
            'release' => [(int) $m[1], (int) ($m[2] ?? 0), (int) ($m[3] ?? 0)],
            'pre' => ($m[4] ?? '') !== '' ? $this->prereleaseParts(explode('.', $m[4])) : [],
            'epoch' => 0,
        ];
    }

    /**
     * PEP 440: `[N!]N(.N)*[{a|b|rc}N][.postN][.devN][+local]`.
     *
     * 🛑 `.post` is a RELEASE, not a prerelease — `1.0.post1` is newer than
     * `1.0` — while `.dev` is older than everything including its own
     * prereleases. Getting those two backwards is the specific failure
     * §8.6.4 names when it says a project "tagging `1.0rc1` or `1.0.post1`"
     * must not get one order in its list and another in its pointer.
     *
     * @return array{release: list<int>, pre: list<array{0: int, 1: int|string}>, epoch: int}|null
     */
    private function parsePep440(string $text): ?array
    {
        $pattern = '/^(?:(\d+)!)?(\d+(?:\.\d+)*)'
            .'(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?'
            .'(?:[-_.]?(post|rev|r)[-_.]?(\d*))?'
            .'(?:[-_.]?(dev)[-_.]?(\d*))?'
            .'(?:\+[0-9A-Za-z.]+)?$/i';

        if (preg_match($pattern, strtolower(trim($text)), $m) !== 1) {
            return null;
        }

        $release = array_map(intval(...), explode('.', $m[2]));

        /*
         * The ordering key, as four slots after the release numbers:
         *
         *   dev        -1  (older than every prerelease of the same release)
         *   prerelease  0  with a, b, rc ordered among themselves
         *   final       1
         *   post        2  (newer than final)
         *
         * Expressed as prerelease parts so one comparison routine serves all
         * three schemes.
         */
        $pre = [];

        if (($m[7] ?? '') !== '') {
            $pre[] = [0, -1];
            $pre[] = [0, (int) ($m[8] ?? 0)];
        } elseif (($m[3] ?? '') !== '') {
            $pre[] = [0, 0];
            $pre[] = [0, match ($m[3]) {
                'a', 'alpha' => 0,
                'b', 'beta' => 1,
                default => 2,          // c, rc, pre, preview
            }];
            $pre[] = [0, (int) ($m[4] ?? 0)];
        } elseif (($m[5] ?? '') !== '') {
            $pre[] = [0, 2];
            $pre[] = [0, (int) ($m[6] ?? 0)];
        }

        return ['release' => $release, 'pre' => $pre, 'epoch' => (int) $m[1]];
    }

    /**
     * Calendar versioning: a dotted or dashed run of numbers, newest highest.
     *
     * No prerelease vocabulary, because CalVer has none — a project needing
     * one is using semver with a date-shaped major, and `semver` reads that
     * correctly.
     *
     * @return array{release: list<int>, pre: list<array{0: int, 1: int|string}>, epoch: int}|null
     */
    private function parseCalver(string $text): ?array
    {
        if (preg_match('/^(\d{2,4})([.\-_])(\d{1,2})(?:\2(\d{1,2}))?(?:\2(\d+))?$/', trim($text), $m) !== 1) {
            return null;
        }

        $release = [(int) $m[1], (int) $m[3]];

        foreach ([$m[4] ?? '', $m[5] ?? ''] as $part) {
            if ($part !== '') {
                $release[] = (int) $part;
            }
        }

        return ['release' => $release, 'pre' => [], 'epoch' => 0];
    }

    /**
     * semver's prerelease comparison vocabulary: numeric identifiers are
     * compared as numbers and sort below alphanumeric ones.
     *
     * @param  list<string>  $identifiers
     * @return list<array{0: int, 1: int|string}>
     */
    private function prereleaseParts(array $identifiers): array
    {
        $parts = [];

        foreach ($identifiers as $identifier) {
            $parts[] = ctype_digit($identifier) ? [0, (int) $identifier] : [1, $identifier];
        }

        return $parts;
    }

    /**
     * @param  array{release: list<int>, pre: list<array{0: int, 1: int|string}>, epoch: int}  $a
     * @param  array{release: list<int>, pre: list<array{0: int, 1: int|string}>, epoch: int}  $b
     */
    private function comparePartsOf(array $a, array $b): int
    {
        if ($a['epoch'] !== $b['epoch']) {
            return $a['epoch'] <=> $b['epoch'];
        }

        // 🛑 Compared position by position with a zero default, so `1.9` and
        // `1.9.0` are equal and `1.10` beats `1.9` on the SECOND component
        // rather than on the string. This is the `v1.10` / `v1.9` case.
        $length = max(count($a['release']), count($b['release']));

        for ($i = 0; $i < $length; $i++) {
            $difference = ($a['release'][$i] ?? 0) <=> ($b['release'][$i] ?? 0);

            if ($difference !== 0) {
                return $difference;
            }
        }

        // 🛑 A release with a prerelease is OLDER than the same release
        // without one. semver says so and so does PEP 440; the `.post` case
        // reaches here as a prerelease part of [0, 2], which sorts above the
        // empty list rather than below it — see the table in parsePep440().
        if ($a['pre'] === [] || $b['pre'] === []) {
            if ($a['pre'] === $b['pre']) {
                return 0;
            }

            $present = $a['pre'] === [] ? $b['pre'] : $a['pre'];
            $presentIsNewer = ($present[0][1] ?? 0) === 2;

            if ($a['pre'] === []) {
                return $presentIsNewer ? -1 : 1;
            }

            return $presentIsNewer ? 1 : -1;
        }

        return $this->comparePrereleases($a['pre'], $b['pre']);
    }

    /**
     * @param  list<array{0: int, 1: int|string}>  $a
     * @param  list<array{0: int, 1: int|string}>  $b
     */
    private function comparePrereleases(array $a, array $b): int
    {
        $length = max(count($a), count($b));

        for ($i = 0; $i < $length; $i++) {
            // A shorter prerelease sorts lower when every preceding part is
            // equal: semver's "1.0.0-alpha < 1.0.0-alpha.1".
            if (! isset($a[$i])) {
                return -1;
            }

            if (! isset($b[$i])) {
                return 1;
            }

            // Numeric identifiers always sort below alphanumeric ones.
            if ($a[$i][0] !== $b[$i][0]) {
                return $a[$i][0] <=> $b[$i][0];
            }

            $difference = $a[$i][0] === 0
                ? ((int) $a[$i][1] <=> (int) $b[$i][1])
                : strcmp((string) $a[$i][1], (string) $b[$i][1]);

            if ($difference !== 0) {
                return $difference;
            }
        }

        return 0;
    }
}
