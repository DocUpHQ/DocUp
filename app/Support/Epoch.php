<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Support;

/**
 * 🛑 §10.8's invalidation registry — one registry, seven epochs.
 *
 * §10.8 opens with the reason it exists: "One registry, because ten
 * uncoordinated counters produce an irreproducible stale-authorisation bug.
 * Every epoch below MUST declare what bumps it, which caches key on it, its
 * maximum tolerated staleness, its fail-closed behaviour when the feed is
 * unavailable, and **one test proving a bump takes effect within its bound**."
 *
 * So each case here answers all five questions, beside the case rather than in a
 * document that drifts from it. An epoch whose properties live somewhere else is
 * an epoch nobody can reason about at 3am, which is the only time anybody reads
 * about cache invalidation.
 *
 * **All seven are declared; not all are implemented.** §17 gives the registry to
 * Phase 04 and says it is "extended by each epoch's owning phase". Declaring an
 * epoch is not inventing a feature — it is recording a commitment the
 * specification already made, in the one place that is supposed to hold it.
 * {@see self::isImplemented()} says which are live, so the registry cannot
 * quietly imply protection that does not exist yet.
 */
enum Epoch: string
{
    /** §8.9.10: in the resolution cache key, so staleness is structurally 0. */
    case Routing = 'routing_epoch';

    /** §12: policy, rule, binding and visibility changes. */
    case Authz = 'authz_epoch';

    /** §8.12: reader deprovision, group change, session revoke. */
    case Identity = 'identity_epoch';

    /** §8.13.3: role assignment changes, for the dashboard's permission cache. */
    case Permission = 'permission_epoch';

    /** §8.8.4: publish and rollback, for the manifest cache. */
    case Serving = 'serving_epoch';

    /** §8.16: reindex, for the search filter. */
    case SearchGeneration = 'search_generation';

    /** §8.12.21: policy writes, for search gating. */
    case PolicyGeneration = 'policy_generation';

    /** What bumps it (§10.8). */
    public function bumpedBy(): string
    {
        return match ($this) {
            self::Routing => 'domain, mount, redirect, version pointer change',
            self::Authz => 'policy, rule, binding, visibility change',
            self::Identity => 'reader deprovision, group change, session revoke',
            self::Permission => 'role assignment change',
            self::Serving => 'publish, rollback',
            self::SearchGeneration => 'reindex',
            self::PolicyGeneration => 'policy write',
        };
    }

    /** Which caches key on it (§10.8). */
    public function keys(): string
    {
        return match ($this) {
            self::Routing => 'resolution cache',
            self::Authz => 'decision caches, grant `ep`',
            self::Identity => 'grant `ep`',
            self::Permission => 'dashboard permission cache',
            self::Serving => 'manifest cache',
            self::SearchGeneration => 'search filter',
            self::PolicyGeneration => 'search gating',
        };
    }

    /**
     * Maximum tolerated staleness (§10.8).
     *
     * 🛑 The two zeroes are achieved structurally rather than promised.
     * `routing_epoch` is **in the cache key** (§8.9.10), so a bump addresses
     * different keys and there is no window in which a stale entry can be read
     * at all. `serving_epoch` moves under the §8.8.4 compare-and-swap, inside
     * the transaction holding the version row — so there is no moment at which
     * the pointer and the epoch disagree.
     *
     * An epoch whose staleness is "0" because something is *purged* promptly
     * would be a different and much weaker claim.
     */
    public function maxStaleness(): string
    {
        return match ($this) {
            self::Routing => '0 (in key)',
            self::Authz, self::Identity => '1 request at Tier A/B; grant TTL + feed interval at Tier C',
            self::Permission => '1 request',
            self::Serving => '0 (CAS)',
            self::SearchGeneration, self::PolicyGeneration => 'fail closed',
        };
    }

    /**
     * Whether an unavailable feed must fail closed (§10.8).
     *
     * 🛑 §8.12.21 makes the search epochs fail closed, and the asymmetry is
     * deliberate: a stale *routing* answer serves the wrong page, which is bad;
     * a stale *search gating* answer returns documents the reader may not read,
     * which is a disclosure. So search degrades to returning nothing rather than
     * to returning what it last knew.
     */
    public function failsClosed(): bool
    {
        return match ($this) {
            self::SearchGeneration, self::PolicyGeneration => true,
            default => false,
        };
    }

    /** The phase that owns the bumping behaviour (§17). */
    public function ownedByPhase(): string
    {
        return match ($this) {
            self::Routing => 'P04',
            self::Serving => 'P03',
            self::Authz => 'P21',
            self::Identity => 'P21',
            self::Permission => 'P02',
            self::SearchGeneration => 'P16',
            self::PolicyGeneration => 'P21',
        };
    }

    /**
     * Whether anything bumps it yet.
     *
     * 🛑 Honest about the gap rather than silent. A registry listing seven
     * epochs reads as seven working controls; four of these have a column, a
     * declaration and nothing that moves them. §8.13.3's permission epoch is
     * the one already recorded as owed from Phase 02 — it has a column and is
     * not compared per request — and it is listed here as unimplemented for the
     * same reason it is listed in the build log: an unenforced control that
     * looks enforced is worse than an absent one.
     */
    public function isImplemented(): bool
    {
        return match ($this) {
            self::Routing, self::Serving => true,
            default => false,
        };
    }
}
