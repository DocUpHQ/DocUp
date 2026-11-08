<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

use App\Auth\Providers\Drivers\ReaderTokenDriver;
use App\Auth\Providers\Drivers\SharedLinkDriver;
use App\Auth\RoleResolver;

/**
 * 🛑 What §8.12.25's "as this identity" is allowed to mean.
 *
 * Three cases, and the list is closed on purpose. §8.12.1 gives this
 * installation exactly two principal populations — `users` for the dashboard
 * and `reader_identities` for published documentation — and the third case is
 * the absence of both. There is no fourth, because a fourth would be an
 * identity the serving path cannot produce, and a simulator that answers for
 * identities that cannot exist answers the wrong question.
 *
 * 🛑 **No "hypothetical identity" case, and the omission is the design.** The
 * tempting fourth entry is "somebody holding a share link" or "somebody with a
 * reader token" — and both are unreachable honestly. §9.1.4 stores those
 * secrets hashed, so the simulator cannot present one to
 * {@see SharedLinkDriver} or
 * {@see ReaderTokenDriver}, and the only way to
 * produce the leaf would be to hand-build a {@see ReaderContext} — a second
 * answer to the question §17 insists has one. {@see PolicySimulator} therefore
 * **reports** those leaves as unsimulatable instead of faking them, which is
 * the difference between a tool an operator can rely on and one that is
 * occasionally confidently wrong.
 */
enum SimulatedIdentityKind: string
{
    /** Nobody: no session, no credential. What a crawler is. */
    case Anonymous = 'anonymous';

    /**
     * A stored `reader_identities` row — §8.12.1's documentation population.
     *
     * Reaches `authenticated` and the `{binding}` leaf of the binding that
     * vouched for it, never `members`: §12.3 reserves that rung for an identity
     * mapping to a role assignment on this organisation, and §8.12.1 forbids a
     * reader identity from holding one.
     */
    case Reader = 'reader';

    /**
     * A stored `users` row — a dashboard member who completed §8.12.10's
     * handoff.
     *
     * The one kind that can reach `members`, and only when
     * {@see RoleResolver} says they hold a role on the project.
     */
    case Member = 'member';
}
