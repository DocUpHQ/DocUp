<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * §20.3's `access_decisions`: every denial, every challenge, and allows
 * aggregated.
 *
 * | Rows | Retention | Rule |
 * |---|---|---|
 * | denials, challenges | 90 days | one row each |
 * | aggregated allows | 90 days | "One row per session, version and hour" |
 *
 * 🛑 **The asymmetry is the feature.** A denial is evidence and each one
 * matters — §8.12.22's containment self-test, §8.12.25's simulator and any
 * incident review all read individual denials. An allow is volume: a reader
 * opening a page with sixty assets authorises sixty times, and sixty rows per
 * page view is the shape that makes an access log unaffordable, then switched
 * off, then absent when it is needed.
 *
 * The aggregation is done by a **nullable unique key** rather than by a branch:
 * `aggregate_key` is a digest for an allow and NULL for a denial, MySQL permits
 * any number of NULLs in a unique index, and the upsert increments. So there is
 * no code path that writes an allow and escapes the aggregation, and no second
 * table to keep in step.
 *
 * ## 🛑 A proposed amendment to §20.3, recorded rather than taken silently
 *
 * §20.3's rule is "one row per session, version **and hour**" — three
 * dimensions. This implementation uses **four**, adding the surface, and the
 * reason is that §17's Phase 21 exit criterion introduced `{proxy, download,
 * search, addons}` as an axis of the decision after §20.3 was written. With
 * three dimensions the `surface` column would hold whichever surface happened
 * to be first in the hour and would be wrong for the rest — a column that lies
 * is worse than a column that is absent. Four dimensions bounds the row count
 * at 4× the stated figure, which is a constant, not a growth rate.
 */
final class DecisionLog
{
    /**
     * Record one decision.
     *
     * 🛑 **Recording must never be able to refuse a request.** The decision has
     * already been made by {@see EffectiveAccess} and the reader is already
     * being answered; a failure here — a missing partition, a full disk, a
     * contended key — must degrade the audit trail and not the service. So
     * every error is swallowed, and the thing that makes that safe rather than
     * negligent is `pmax`: the partition layout cannot overflow, so the one
     * predictable cause of failure is already handled in the schema.
     *
     * @param  string|null  $organisationId  raw 16 bytes
     * @param  string|null  $projectId  raw 16 bytes
     * @param  string|null  $versionId  raw 16 bytes
     * @param  string|null  $mountId  raw 16 bytes
     * @param  int  $now  unix seconds, so the caller's clock is the only clock
     */
    public static function record(
        AccessDecision $decision,
        AccessSurface $surface,
        ?string $organisationId,
        ?string $projectId,
        ?string $versionId,
        ?string $mountId,
        ?string $subject,
        int $authzEpoch,
        int $now,
    ): void {
        try {
            self::write($decision, $surface, $organisationId, $projectId, $versionId, $mountId, $subject, $authzEpoch, $now);
        } catch (\Throwable) {
            // See the method note: the trail degrades, the request does not.
        }
    }

    /**
     * 🛑 §20.3's keyed digest of a reader subject — never the subject itself.
     *
     * §20.3 gives a raw IP a seven-day retention in `security_events` and calls
     * that "the only place a raw IP exists"; `access_decisions` keeps ninety
     * days, so nothing identifying may reach it. Keyed with the application key
     * rather than plainly hashed, because an unkeyed digest of a small domain —
     * and a session handle is drawn from one — is reversible by enumeration.
     *
     * Returns null for an anonymous reader, which has no subject to key.
     */
    public static function subjectHash(?string $subject): ?string
    {
        if ($subject === null || $subject === '') {
            return null;
        }

        $key = config('app.key');

        return hash_hmac('sha256', $subject, is_string($key) ? $key : '', binary: true);
    }

    /**
     * The hour bucket an allow aggregates into, or null for a denial.
     *
     * 16 bytes so it fits the column's `BINARY(16)`, taken from the front of a
     * SHA-256 over the four dimensions. Truncation is safe here: this is a
     * bucket identifier, not a security boundary — a collision would merge two
     * readers' allow counts in one hour, and 128 bits makes that
     * astronomically unlikely in a table scoped to ninety days.
     *
     * @param  string|null  $versionId  raw 16 bytes
     */
    public static function aggregateKey(
        AccessDecision $decision,
        AccessSurface $surface,
        ?string $subjectHash,
        ?string $versionId,
        int $now,
    ): ?string {
        if (! $decision->allowed) {
            // 🛑 NULL, which is what makes the unique key aggregate allows and
            // leave denials alone.
            return null;
        }

        return substr(hash(
            'sha256',
            implode('|', [
                $subjectHash === null ? 'anonymous' : bin2hex($subjectHash),
                $versionId === null ? 'none' : bin2hex($versionId),
                (string) intdiv($now, 3600),
                $surface->value,
            ]),
            binary: true,
        ), 0, 16);
    }

    /**
     * @param  string|null  $organisationId  raw 16 bytes
     * @param  string|null  $projectId  raw 16 bytes
     * @param  string|null  $versionId  raw 16 bytes
     * @param  string|null  $mountId  raw 16 bytes
     */
    private static function write(
        AccessDecision $decision,
        AccessSurface $surface,
        ?string $organisationId,
        ?string $projectId,
        ?string $versionId,
        ?string $mountId,
        ?string $subject,
        int $authzEpoch,
        int $now,
    ): void {
        $subjectHash = self::subjectHash($subject);
        $aggregateKey = self::aggregateKey($decision, $surface, $subjectHash, $versionId, $now);

        $row = [
            'id' => Uuid::v7(),
            'decided_on' => date('Y-m-d', $now),
            'decided_at' => date('Y-m-d H:i:s', $now),
            'organisation_id' => $organisationId,
            'project_id' => $projectId,
            'version_id' => $versionId,
            'mount_id' => $mountId,
            'outcome' => $decision->allowed ? 'allow' : ($decision->challenge ? 'challenge' : 'deny'),
            'surface' => $surface->value,
            'status' => $decision->status,
            'reason_code' => $decision->reason->value,
            'rule_id' => $decision->rule?->id === null ? null : Uuid::tryToBytes($decision->rule->id),
            'required_level' => $decision->required->value,
            'established_level' => $decision->established->value,
            'satisfied_by' => $decision->satisfiedBy?->value,
            'subject_hash' => $subjectHash,
            'aggregate_key' => $aggregateKey,
            'occurrences' => 1,
            'authz_epoch' => $authzEpoch,
        ];

        if ($aggregateKey === null) {
            DB::table('access_decisions')->insert($row);

            return;
        }

        /*
         * 🛑 One statement, and it has to be. A read-then-write would lose
         * counts under concurrency — which is the normal case here, since the
         * sixty parallel asset requests of one page view are exactly what this
         * aggregation exists for.
         *
         * `occurrences + 1` computed in SQL rather than in PHP, for the reason
         * `Invalidation` gives about epochs: a value computed in the
         * application cannot survive a concurrent writer.
         */
        DB::statement(
            'INSERT INTO `access_decisions` ('.implode(', ', array_map(
                static fn (string $column): string => '`'.$column.'`',
                array_keys($row),
            )).') VALUES ('.implode(', ', array_fill(0, count($row), '?')).')
             ON DUPLICATE KEY UPDATE `occurrences` = `occurrences` + 1, `decided_at` = VALUES(`decided_at`)',
            array_values($row),
        );
    }
}
