<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Federation;

/**
 * The closed set of things an inbound provisioning request can ask for.
 *
 * 🛑 Five cases and not four: `Deactivate` and `Delete` are separate because a
 * directory means different things by them and DocUp must not collapse them.
 * SCIM 2.0 has both — `PATCH active:false` and `DELETE /Users/{id}` — and
 * treating the first as the second would make a temporary suspension
 * irreversible.
 */
enum ProvisioningAction: string
{
    /** A reader the directory has not sent before. */
    case Create = 'create';

    /**
     * An existing reader's attributes or groups changed.
     *
     * 🛑 §8.13.7's reconciliation is "added **and** removed", so an update
     * carries the whole group membership rather than a delta. A delta-shaped
     * seam would make a dropped message into a group that never goes away.
     */
    case Update = 'update';

    /**
     * 🛑 The reader may no longer read, and may come back.
     *
     * Stamps `reader_identities.deprovisioned_at`, which the login path and
     * §8.12.25's simulator already refuse on — the column has existed since P24
     * and, until this seam, nothing wrote it.
     *
     * Reversible by {@see self::Reactivate}, which is why it is not `Delete`:
     * a leave of absence, a suspended contractor and a locked account are all
     * this, and an irreversible deletion would lose the group memberships they
     * come back to.
     */
    case Deactivate = 'deactivate';

    /** The reader is back, and their memberships with them. */
    case Reactivate = 'reactivate';

    /**
     * 🛑 The directory says the identity should not exist at all.
     *
     * Distinct from `Deactivate` and **deliberately the harder one**: §20's
     * retention model gives soft-deleted rows "30 days, mandatory hard purge",
     * and an identity's `subject_hash` is the only thing linking a decision-log
     * row to a person. A `Delete` that purged immediately would erase the
     * evidence of what the reader read on their last day, which is the one day
     * anybody asks about.
     */
    case Delete = 'delete';
}
