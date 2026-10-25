<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

use App\Models\Build;

/**
 * One successful build of a component, as a selector sees it.
 *
 * The three fields are the three things §8.7.5's selectors ask about: which
 * ref it came from, what version label that ref carries under the source's
 * strategy, and the build itself. Assembled once per resolution so the
 * label is derived once rather than inside every comparison.
 */
final class Candidate
{
    private ?SemanticVersion $version = null;

    private bool $parsed = false;

    public function __construct(
        public readonly Build $build,
        public readonly ?string $ref,
        public readonly ?string $label,
    ) {}

    /**
     * The label as a comparable version, or null when it is not one.
     *
     * Memoised because an ordering compares each candidate against the
     * running best, so a set of n candidates parses each label once instead
     * of n times. The `$parsed` flag rather than a null check: null is a
     * real answer here — "this label is a branch name" — and re-parsing it
     * on every comparison is the case that costs most, since an
     * unparseable label is the one every branch build has.
     */
    public function version(): ?SemanticVersion
    {
        if (! $this->parsed) {
            $this->version = $this->label === null ? null : SemanticVersion::parse($this->label);
            $this->parsed = true;
        }

        return $this->version;
    }
}
