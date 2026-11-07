<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

use App\Auth\AccessLevel;

/**
 * Everything {@see EffectiveAccess} is allowed to know.
 *
 * 🛑 **The four lattice columns arrive as four values, all authoritative.**
 * §12.3: "No column in this lattice is ever derived at read time from another;
 * all four are stored and all four are authoritative at decision time." So they
 * are four parameters rather than one pre-computed "effective visibility" — a
 * caller that collapsed them would be making part of the decision outside the
 * one function that is allowed to make it, and the reason code would no longer
 * be able to say which column refused.
 *
 * 🛑 **There is no `isPublic` shortcut and no cached verdict**, which is
 * §8.12.14:
 *
 * > "There MUST be **no public fast path** that bypasses an authorisation
 * > decision on a cached `is_public` flag. A stale read in the unsafe direction
 * > serves private bytes with no decision at all, which is a worse class of bug
 * > than a stale allow for an already-authorised reader."
 *
 * Every request builds one of these and calls the function. The decision is
 * cheap — no I/O, no clock beyond the `now` passed in — so the fast path and
 * the slow path are the same path.
 */
final class AccessRequest
{
    /**
     * @param  string  $projectId  raw 16 bytes
     * @param  AccessLevel  $projectVisibility  §8.2.10's kill switch
     * @param  AccessLevel  $versionVisibility  §8.6.2
     * @param  string  $mountExposure  §10.5's lattice **plus `inherit`**, as
     *                                 stored. Resolved inside the function, not
     *                                 by the caller: `inherit` means "take the
     *                                 project's value" and resolving it outside
     *                                 would be a caller deciding one of §12.3's
     *                                 conjuncts.
     * @param  AccessLevel|null  $componentMinAccess  §8.7.7's ceiling from the
     *                                                published manifest, or null
     *                                                when no component matched.
     *                                                🛑 Supplied only after
     *                                                mount matching, which is
     *                                                what "re-evaluated on every
     *                                                request after mount
     *                                                matching" means.
     * @param  string  $path  normalised, relative to the version root
     * @param  int  $now  unix seconds, passed in rather than read — so the
     *                    function stays pure and the decision table can assert
     *                    a `not_after` boundary without waiting for it
     * @param  int  $searchGeneration  §8.12.21; compared against
     *                                 `$policyGeneration` for the search surface
     * @param  bool  $existencePublic  🛑 §8.12.23's case (b): "the resource's
     *                                 **existence is already public**, because
     *                                 the project appears in the
     *                                 visibility-filtered index of §8.2.7". The
     *                                 caller knows whether the project is in
     *                                 that index; the function must not guess,
     *                                 because guessing wrong in one direction
     *                                 turns a 404 into a confirmation.
     * @param  bool  $bindingDegraded  🛑 §8.12.19: a degraded binding denies and
     *                                 never falls back to another provider or to
     *                                 public
     */
    public function __construct(
        public readonly string $projectId,
        public readonly AccessLevel $projectVisibility,
        public readonly AccessLevel $versionVisibility,
        public readonly string $mountExposure,
        public readonly ReaderPolicy $policy,
        public readonly ReaderContext $reader,
        public readonly string $versionSlug,
        public readonly string $language = 'en',
        public readonly string $path = '/',
        public readonly AccessSurface $surface = AccessSurface::Proxy,
        public readonly ?AccessLevel $componentMinAccess = null,
        public readonly int $denyStatus = 404,
        public readonly int $now = 0,
        public readonly int $policyGeneration = 0,
        public readonly int $searchGeneration = 0,
        public readonly bool $existencePublic = false,
        public readonly bool $bindingDegraded = false,
    ) {}

    /**
     * §12.3's `inherit` resolution: "which means 'take the project's value' and
     * is resolved before the comparison".
     *
     * 🛑 An unrecognised value resolves to the project's visibility too, not to
     * `public`. A column value this code has not been taught must not weaken
     * anything — the same fail-safe direction `MountExposure::effective()`
     * takes on the write side.
     */
    public function resolvedMountExposure(): AccessLevel
    {
        return AccessLevel::tryFrom($this->mountExposure) ?? $this->projectVisibility;
    }
}
