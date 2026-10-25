<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

/**
 * Why a composition write was refused, as a stable identifier.
 *
 * 🛑 §8.1.11 public contract, like every other rejection enum in this
 * repository: these values reach the audit log, the dashboard and an
 * operator's tooling, so renaming one breaks something outside it.
 *
 * 🛑 **Every value here is a refusal, never a warning.** §8.7.7 is
 * categorical — "Mounting a component whose ceiling is stricter than the
 * target version's effective visibility MUST be **refused, not warned**" —
 * and the reason is in the same sentence: without it "any project admin in
 * the organisation can mount any component onto a public project — a
 * declassification primitive in a product whose headline feature is
 * per-project authentication". A warning is a refusal somebody clicked past.
 */
enum CompositionRejection: string
{
    /**
     * 🛑 §8.7.7's ceiling. The component is more confidential than the
     * version it was about to be published on.
     */
    case CeilingExceeded = 'composition.min_access_ceiling_exceeded';

    /** 🛑 §8.7.8: mounting a component the mounting team does not own. */
    case GrantMissing = 'composition.grant_missing';

    /** §8.7.3: `UNIQUE (project_version_id, component_id)`. */
    case ComponentAlreadyMounted = 'composition.component_already_mounted';

    /** §8.7.3: `UNIQUE (project_version_id, mount_path_hash)`. */
    case MountPathTaken = 'composition.mount_path_taken';

    /** §8.7.3: at most one primary mount per project version. */
    case PrimaryMountExists = 'composition.primary_mount_exists';

    /**
     * §8.7.3: "the two halves the index cannot enforce — that **at least
     * one** exists, and that it sits at `mount_path=''`".
     */
    case PrimaryMountMissing = 'composition.primary_mount_missing';
    case PrimaryMountNotAtRoot = 'composition.primary_mount_not_at_root';

    /**
     * 🛑 **Retired in Phase 14, and kept because it was once emitted.**
     *
     * Phase 13 refused every second mount with this identifier, naming
     * §8.7.6's nav splicing, §8.7.14's collision policy and §8.7.15's
     * shadowing refusal as the reason — all three had to land together.
     * They did, so nothing produces it any more and
     * {@see self::MountPathShadows} is the narrow refusal that replaced it.
     *
     * The case stays because §8.1.11 makes these values public contract:
     * an operator's alert rule or an audit export may still carry it, and
     * a value that cannot be looked up is worse than one that resolves to
     * "this no longer happens, and here is what does".
     */
    case MultipleMountsNotYetSupported = 'composition.multiple_mounts_not_yet_supported';

    /** §8.7.15, which P14 implements in full with its override redirects. */
    case MountPathShadows = 'composition.mount_path_shadows';

    /**
     * 🛑 §8.7.14: "Output path collisions MUST fail the build by default,
     * naming **both** contributing sources and the exact path."
     *
     * The detail carries all three, because a bare identifier would send an
     * operator through every mounted repository looking for the other half.
     */
    case PathCollision = 'composition.path_collision';

    /**
     * §8.7.14's refused tie: `priority_wins` with two equal priorities.
     *
     * Refused rather than broken arbitrarily, because an author who set a
     * precedence strategy believed they had expressed an order.
     */
    case CollisionPriorityTie = 'composition.collision_priority_tie';

    /**
     * 🛑 §8.7.20: "New publications MUST fail closed when a required mount
     * cannot resolve."
     */
    case RequiredMountUnresolved = 'composition.required_mount_unresolved';

    /**
     * §8.7.6: "an unresolvable include on a required mount fails the
     * publish."
     */
    case NavIncludeUnresolvable = 'composition.nav_include_unresolvable';

    /**
     * §8.8.7's gate: a release-kind version whose composition has drifted
     * and whose drift event nobody has approved.
     */
    case DriftApprovalRequired = 'composition.drift_approval_required';

    /** A mount path that is not a canonical, slash-free-at-the-edges prefix. */
    case MountPathNotCanonical = 'composition.mount_path_not_canonical';

    /** §8.7.1: `UNIQUE (organisation_id, key)`. */
    case ComponentKeyTaken = 'composition.component_key_taken';

    /**
     * §8.7.7's loosening: "Loosening a ceiling MUST be a separate audited
     * action that re-validates every existing mount and unpublishes any
     * version it would declassify."
     *
     * This is the refusal for the other direction — TIGHTENING a ceiling
     * past a version that is already published on it, which would
     * retroactively make a live mount invalid.
     */
    case CeilingTighteningWouldOrphanMounts = 'composition.ceiling_tightening_would_orphan_mounts';

    public function identifier(): string
    {
        return $this->value;
    }
}
