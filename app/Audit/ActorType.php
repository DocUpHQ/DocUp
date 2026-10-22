<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Audit;

/**
 * What kind of thing performed an audited action.
 *
 * 🛑 Only the type is readable; the actor itself is an opaque identifier
 * (§8.22.5). The human-readable label lives in `actor_labels`, which erasure
 * overwrites with a tombstone — so the chain keeps verifying after a person is
 * erased, because nothing erasable was ever hashed.
 */
enum ActorType: string
{
    case User = 'user';
    case ApiToken = 'api_token';
    case Group = 'group';

    /**
     * The installation itself: scheduled jobs, migrations, maintenance.
     *
     * Distinct from a user with administrative rights, and the distinction
     * matters when reading a log after an incident: "the system purged this"
     * and "a person purged this" are different events, and conflating them
     * makes an automated action look like a human decision.
     */
    case System = 'system';
}
