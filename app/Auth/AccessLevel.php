<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth;

/**
 * 🛑 **One access lattice, four columns** (§12.3).
 *
 * `components.min_access`, `projects.visibility`,
 * `project_versions.visibility` and `domain_mounts.mount_exposure` all draw
 * from this same ordered four-value scale. That is the point of putting it in
 * one enum: §12.3 wants "permits", "stricter" and "narrows" to be **one
 * relation rather than three mappings**, and four independent string columns
 * with four comparison helpers is how they drift apart.
 *
 * Phase 02 uses it for `projects.visibility` only, which §8.2.10 makes the
 * operator's single kill switch. The reader-side decision function that
 * consumes all four — `EffectiveAccess` — arrives in Phase 21, and this enum
 * deliberately contains **no decision logic**: only the ordering and the three
 * relations §12.3 defines on it. Access decisions have exactly one call site
 * (§4.3/7) and it is not here.
 *
 * `domain_mounts.mount_exposure` additionally keeps an `inherit` sentinel
 * meaning "take the project's value". That is resolved to one of these four
 * before any comparison, so it is not a case here.
 */
enum AccessLevel: string
{
    /** Any reader, no credential. */
    case Public = 'public';

    /** Any reader who satisfied any identity leaf of any binding in scope. */
    case Authenticated = 'authenticated';

    /** A reader whose identity maps to a role assignment or group on this organisation. */
    case Members = 'members';

    /** Only a reader satisfying an explicit allow rule naming this component or version. */
    case Restricted = 'restricted';

    /**
     * Position on the scale, weakest first (§12.3).
     *
     * The numbers are the specification's own, and every relation below is
     * expressed in terms of this so there is a single source of ordering.
     */
    public function order(): int
    {
        return match ($this) {
            self::Public => 0,
            self::Authenticated => 1,
            self::Members => 2,
            self::Restricted => 3,
        };
    }

    /**
     * `narrows(a, b)` — true when `order(a) >= order(b)` (§12.3).
     *
     * 🛑 §8.12.8 requires `mount_exposure` to satisfy `narrows(mount_exposure,
     * project.visibility)`, and a write that would not is **refused**. A
     * per-domain profile may only ever tighten access, never widen it:
     * otherwise mounting a project on a second domain becomes a way to publish
     * what the project's own visibility forbids.
     */
    public function narrows(self $other): bool
    {
        return $this->order() >= $other->order();
    }

    /**
     * `stricter(a, b)` — true when `order(a) > order(b)` (§12.3, §8.7.7).
     *
     * Note this is strict where {@see self::narrows()} is not. §8.7.7 refuses a
     * component mount when `stricter(component.min_access, effective
     * visibility)`: a component that demands more than its target can offer
     * would be silently under-protected by being mounted there.
     */
    public function stricter(self $other): bool
    {
        return $this->order() > $other->order();
    }

    /** True when this level is at or below the reader's established context. */
    public function permittedBy(self $established): bool
    {
        return $established->order() >= $this->order();
    }
}
