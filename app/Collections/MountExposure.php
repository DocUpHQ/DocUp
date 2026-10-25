<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Collections;

use App\Auth\AccessLevel;
use App\Models\DomainMount;
use App\Models\Project;

/**
 * 🛑 §8.12.8's intersection, on the write side (§12.3).
 *
 * > "Composition MUST NEVER widen access, **without exception**. Effective
 * > access for collections and composed projects MUST be the intersection of
 * > every applicable policy, and a per-domain authentication profile or
 * > exposure override MUST be permitted only where it narrows, enforced as an
 * > intersection and refused at write time otherwise."
 *
 * 🛑 **This is not a second `EffectiveAccess` and must not become one.**
 * §4.3/7 and §12.3 give the reader decision exactly one call site, and it
 * arrives in Phase 21. What lives here is the *write-time* half of §8.12.8 —
 * the refusal — plus the one pure function the read-side decision will
 * consume for the collection axis. The distinction is the same one §12.3
 * draws between `narrows` (a constraint on what may be stored) and `permits`
 * (a decision about a reader), and keeping them in different files is what
 * stops the second turning into the first.
 *
 * So: nothing here takes a reader, a session, an identity or a request.
 */
final class MountExposure
{
    /**
     * The effective exposure of a project served through a mount.
     *
     * The intersection, expressed on §12.3's ordered scale as the **maximum
     * order** of the two — because a higher order is a stronger demand, so
     * intersecting two requirements means taking the stronger. A mount with
     * `inherit` contributes nothing and the project's own value stands, which
     * is what the sentinel means.
     */
    public static function effective(AccessLevel $projectVisibility, string $mountExposure): AccessLevel
    {
        $mount = AccessLevel::tryFrom($mountExposure);

        if ($mount === null) {
            // `inherit`, or a value from a future migration this code has not
            // been taught. Both answer the same way and the reason is the
            // same: an exposure this function cannot interpret must not
            // weaken the project's own, so it contributes nothing.
            return $projectVisibility;
        }

        return $mount->narrows($projectVisibility) ? $mount : $projectVisibility;
    }

    /**
     * 🛑 Refuse a mount exposure that would widen a project's access.
     *
     * §12.3: "`mount_exposure` MUST satisfy `narrows(mount_exposure,
     * project.visibility)`; a write that would not is refused (§8.12.8)."
     *
     * Refused at **write** time, which is the whole of its value: at read
     * time the widened row already exists, and every decision made before
     * somebody noticed it has already been served.
     *
     * @throws CollectionRefused
     */
    public static function assertNarrows(string $mountExposure, AccessLevel $projectVisibility): void
    {
        $mount = AccessLevel::tryFrom($mountExposure);

        if ($mount === null) {
            // `inherit` takes the project's value, so there is nothing to
            // widen. This is the common case and it is always allowed.
            return;
        }

        if (! $mount->narrows($projectVisibility)) {
            throw CollectionRefused::of(
                CollectionRejection::ExposureWidens,
                $mountExposure.' does not narrow '.$projectVisibility->value,
            );
        }
    }

    /** The effective exposure of a stored mount, for a caller holding both rows. */
    public static function of(DomainMount $mount, Project $project): AccessLevel
    {
        return self::effective($project->visibility, $mount->mount_exposure);
    }
}
