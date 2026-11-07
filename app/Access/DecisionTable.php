<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

use App\Auth\AccessLevel;

/**
 * 🛑 §12.3's "**generated exhaustive decision table**", which §17 makes this
 * phase's test.
 *
 * > "The full matrix — `{public, private} × {active, hidden} × {member,
 * > non-member, anonymous} × {proxy, download, search, addons}` — asserted at
 * > 100%."
 *
 * Four axes, 2 × 2 × 3 × 4 = **48 cases**, every one enumerated here and every
 * one driven through the real {@see EffectiveAccess} by
 * `tests/Unit/Access/DecisionTableTest`. The same array renders the operator
 * guide's table, so the documentation and the test cannot disagree — the
 * lesson Phase 17 paid for, where §8.7.13's mode matrix was prose that had
 * drifted from the code.
 *
 * 🛑 **Why generated and not hand-written.** A hand-written matrix of 48 rows
 * is a document somebody maintains; the first time a row is wrong, the wrong
 * row is the one that gets believed. Generated from the axes, the *count* is a
 * property of the enumeration — so a fifth surface or a fifth lattice level
 * changes the number of cases automatically and the test fails until each new
 * case has a stated expectation. That is the difference between a table that
 * proves something and a table that is merely present.
 *
 * ## What each axis is
 *
 * - **visibility** — `project_versions.visibility`, `public` or private. 🛑
 *   "Private" is `members` on §12.3's lattice: §8.6.2 is explicit that "`hidden`
 *   is not `private`", and the lattice has no level called private, so the
 *   exit criterion's informal word is read as the level an operator actually
 *   picks for private documentation. {@see self::expected()} explains why the
 *   non-member case then matters.
 * - **listed** — §8.6.2's `listed` axis, `active` or `hidden`. 🛑 It must make
 *   **no difference** to any of the 48 answers, and that is the point of
 *   including it: a hidden version "serves by direct URL and is absent from the
 *   flyout, sitemap, `llms.txt` and search", so an authorisation decision that
 *   consulted it would have collapsed two of §8.6.2's four independent axes.
 * - **reader** — anonymous, authenticated non-member, member.
 * - **surface** — §8.12.21's four derived surfaces.
 *
 * The project is public in every row, deliberately: §8.2.10 makes
 * `projects.visibility` dominate everything, so a matrix that varied it would
 * have 24 rows whose answer is "the kill switch said no" and would exercise
 * nothing else. The domination has its own test.
 */
final class DecisionTable
{
    /**
     * Every case, in a stable order.
     *
     * @return list<array{
     *     case: int,
     *     visibility: string,
     *     listed: string,
     *     reader: string,
     *     surface: AccessSurface,
     *     allowed: bool,
     *     status: int,
     *     reason: AccessReason,
     *     publicly_cacheable: bool,
     * }>
     */
    public static function cases(): array
    {
        $cases = [];
        $number = 1;

        foreach (['public', 'private'] as $visibility) {
            foreach (['active', 'hidden'] as $listed) {
                foreach (['anonymous', 'non-member', 'member'] as $reader) {
                    foreach (AccessSurface::cases() as $surface) {
                        [$allowed, $status, $reason] = self::expected($visibility, $reader);

                        $cases[] = [
                            'case' => $number++,
                            'visibility' => $visibility,
                            'listed' => $listed,
                            'reader' => $reader,
                            'surface' => $surface,
                            'allowed' => $allowed,
                            'status' => $status,
                            'reason' => $reason,
                            /*
                             * 🛑 §9.3.2's third input. A public version with no
                             * policy row is publicly cacheable; a private one
                             * never is, even for the member who may read it —
                             * "a private version … carries private cache
                             * directives on both axes with no cache tag", which
                             * is §17's exit criterion for this phase.
                             */
                            'publicly_cacheable' => $allowed && $visibility === 'public',
                        ];
                    }
                }
            }
        }

        return $cases;
    }

    /**
     * The {@see AccessRequest} for one case, built against the real types.
     *
     * 🛑 The table drives the **production** decision function with production
     * value objects. A table that compared against a reimplementation of the
     * rules would assert that two copies of the logic agree, which is the one
     * thing a decision table must not be.
     *
     * @param  array{visibility: string, listed: string, reader: string, surface: AccessSurface, ...}  $case
     */
    public static function requestFor(array $case): AccessRequest
    {
        return new AccessRequest(
            projectId: str_repeat("\x11", 16),
            // Public throughout; see the class note on why.
            projectVisibility: AccessLevel::Public,
            versionVisibility: $case['visibility'] === 'public' ? AccessLevel::Public : AccessLevel::Members,
            // `inherit`, the default, so the mount contributes nothing and the
            // version axis is what is being measured.
            mountExposure: 'inherit',
            /*
             * 🛑 No policy row, which is the state every project built before
             * this phase is in — and the state the lattice has to decide alone.
             * The policy axis is exercised by its own tests; mixing it into this
             * matrix would make 48 cases into 48 cases about one policy.
             */
            policy: ReaderPolicy::absent(),
            reader: self::readerFor($case['reader']),
            versionSlug: 'v2',
            surface: $case['surface'],
            now: 1_760_000_000,
        );
    }

    /** The reader context for one axis value. */
    public static function readerFor(string $reader): ReaderContext
    {
        return match ($reader) {
            'member' => ReaderContext::member('subject-member'),
            'non-member' => ReaderContext::authenticated('subject-reader'),
            default => ReaderContext::anonymous(),
        };
    }

    /**
     * The expected outcome, from the two axes that decide one.
     *
     * 🛑 **`listed` and `surface` are absent from this function**, and their
     * absence is an assertion rather than an omission:
     *
     * - `listed` must not affect an authorisation decision at all (§8.6.2:
     *   "`hidden` is not `private`"). If it ever does, 24 of the 48 cases fail.
     * - `surface` must not either, *at equal generations*. The surface axis does
     *   change an answer — §8.12.21 disables search while its generation lags —
     *   but that is a property of the generations, not of the surface, so with
     *   the generations equal all four surfaces agree. The lagging case has its
     *   own test, because a matrix row cannot express "and the index is stale".
     *
     * @return array{0: bool, 1: int, 2: AccessReason}
     */
    private static function expected(string $visibility, string $reader): array
    {
        if ($visibility === 'public') {
            return [true, 200, AccessReason::Allowed];
        }

        if ($reader === 'member') {
            return [true, 200, AccessReason::Allowed];
        }

        /*
         * 🛑 404, not 403, for both the anonymous reader and the authenticated
         * non-member. §8.12.23 makes 404 the default and permits 403 only for
         * an authenticated principal on a project that configured it — and this
         * matrix's project did not, so even the non-member gets 404.
         *
         * 🛑 And the **non-member** row is why "private" is `members` rather
         * than `authenticated`: with `authenticated` the non-member would be
         * allowed, the anonymous reader refused, and the lattice's middle rung
         * would never be tested. A matrix that cannot distinguish "signed in"
         * from "signed in *here*" is a matrix that would pass against an
         * implementation with no `members` level.
         */
        return [false, 404, AccessReason::VersionVisibility];
    }

    /**
     * The table as Markdown, for the operator guide.
     *
     * 🛑 Rendered from {@see self::cases()}, which is also what the test drives,
     * so the published table is the tested one. Phase 17's finding in one
     * method: a matrix maintained beside the code it describes drifts from it,
     * and the drift is invisible because both halves look authoritative.
     */
    public static function toMarkdown(): string
    {
        $lines = [
            '| # | version | listed | reader | surface | result | status | publicly cacheable | reason |',
            '|---|---|---|---|---|---|---|---|---|',
        ];

        foreach (self::cases() as $case) {
            $lines[] = sprintf(
                '| %d | %s | %s | %s | `%s` | **%s** | `%d` | %s | `%s` |',
                $case['case'],
                $case['visibility'],
                $case['listed'],
                $case['reader'],
                $case['surface']->value,
                $case['allowed'] ? 'allow' : 'deny',
                $case['status'],
                $case['publicly_cacheable'] ? 'yes' : 'no',
                $case['reason']->value,
            );
        }

        return implode("\n", $lines)."\n";
    }
}
