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
     * §17 Phase 13: "Explicitly not in scope: More than one component per
     * project version (P14)."
     *
     * A refusal rather than an untested success. The schema accommodates it
     * and the resolver reads a list, but the nav splicing of §8.7.6, the
     * collision policy of §8.7.14 and the shadowing refusal of §8.7.15 are
     * all P14's — and a second mount today would serve with none of them.
     */
    case MultipleMountsNotYetSupported = 'composition.multiple_mounts_not_yet_supported';

    /** §8.7.15, which P14 implements in full with its override redirects. */
    case MountPathShadows = 'composition.mount_path_shadows';

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
