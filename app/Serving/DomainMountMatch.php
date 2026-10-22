<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * Which domain mount a path belongs to, and what is left after its prefix.
 *
 * The domain-level twin of {@see MountMatch}, and it exists for the same
 * reason: §7.3's boundary rule is applied once, by {@see SegmentPrefix}, and the
 * result carries both halves. Returning only the mount left the caller to strip
 * the prefix a second time, which meant a second implementation of the boundary
 * rule and a defensive branch for the case where the two disagreed.
 */
final class DomainMountMatch
{
    /** @param  string  $remainder  the path after the mount prefix, no leading slash */
    public function __construct(
        public readonly SnapshotMount $mount,
        public readonly string $remainder,
    ) {}
}
