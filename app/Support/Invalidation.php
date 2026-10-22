<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Support;

use App\Audit\ActorType;
use App\Audit\Audit;
use Illuminate\Contracts\Database\Query\Expression;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 The one place an epoch is bumped (§10.8).
 *
 * §10.8: "One registry, because ten uncoordinated counters produce an
 * irreproducible stale-authorisation bug." A registry that only *described* the
 * epochs would leave the counters uncoordinated anyway, so the bumping lives
 * here too — and an architecture test asserts that nothing else increments one.
 *
 * Each bump is a single atomic SQL increment, never a read-modify-write. Two
 * concurrent domain changes must both be reflected: with `routing_epoch = ? + 1`
 * computed in PHP, the second write would overwrite the first and the cache key
 * would stay where one of them left it. `routing_epoch + 1` in SQL cannot lose
 * a bump.
 */
final class Invalidation
{
    /**
     * Bump a project's `routing_epoch` (§8.9.10).
     *
     * 🛑 Per **project**, which §8.9.10 is explicit about: the epoch is "the
     * **project's** `routing_epoch` … so that one project's domain change cannot
     * invalidate every other project's resolution cache". A single
     * installation-wide counter would make every domain edit a full cache flush,
     * and on a busy installation that is a thundering herd on the hottest path.
     *
     * Staleness is 0 because the epoch is *in* the resolution cache key — a
     * bump addresses different keys, so there is no window in which a stale
     * entry can be read. Nothing is purged and nothing needs to be.
     *
     * @param  string  $projectId  raw 16 bytes
     * @param  string  $cause  one of §10.8's four: domain, mount, redirect,
     *                         version pointer change
     * @param  string|null  $organisationId  raw 16 bytes, for the audit record
     * @param  string|null  $actorId  raw 16 bytes, or null when the system did it
     */
    public static function bumpRouting(
        string $projectId,
        string $cause,
        ?string $organisationId = null,
        ?string $actorId = null,
    ): void {
        $affected = DB::table('projects')
            ->where('id', $projectId)
            // Atomic. See the class note: a value computed in PHP loses a
            // concurrent bump, and losing a bump means serving stale routing.
            ->update(['routing_epoch' => DB::raw('`routing_epoch` + 1')]);

        if ($affected === 0 || $organisationId === null) {
            /*
             * A soft-deleted or absent project needs no bump, and without an
             * organisation there is no chain to append to. Not an error:
             * §8.22.6's recovery window means a deleted project's rows are
             * still there, and bumping an epoch nothing reads is harmless.
             */
            return;
        }

        Audit::record(
            action: 'epoch.bumped',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $organisationId,
            actorId: $actorId,
            subjectType: 'project',
            subjectId: $projectId,
            // §8.22.5: identifiers and fixed vocabulary only. `cause` is one of
            // §10.8's four named triggers, not free text.
            payload: ['epoch' => Epoch::Routing->value, 'cause' => $cause],
        );
    }

    /**
     * The increment expression for `serving_epoch` (§8.8.4, §10.8).
     *
     * 🛑 An **expression**, not an update, and that is the point. §8.8.4 makes
     * publication "a **single** compare-and-swap row update", so the epoch has
     * to move *inside* that one statement rather than in a second one beside
     * it. Returning the expression lets the Publisher fold it into its CAS while
     * this class stays the only place that knows how an epoch advances — which
     * is what §10.8's "one registry" is for.
     *
     * The first version performed its own UPDATE. Functionally fine, inside the
     * same transaction and the same row lock, but it made §8.8.4's "single row
     * update" two statements — and the test asserting that criterion caught it.
     * Folded in, §10.8's "0 (CAS)" staleness is literal rather than argued: the
     * pointer and the epoch are the same write.
     *
     * Not audited separately. The flip it rides on is already audited as
     * `version.published` or `version.rolled_back`, and a second record of one
     * event would double every publish in the chain for no extra fact.
     */
    public static function servingEpochIncrement(): Expression
    {
        return DB::raw('`serving_epoch` + 1');
    }
}
