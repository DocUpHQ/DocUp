<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Audit;

use App\Audit\Exceptions\AuditKeyMissing;
use App\Audit\Exceptions\ChainLockUnavailable;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * Writes the hash-chained audit log (§8.22.1, §8.22.4, §8.22.5).
 *
 * `hash = HMAC(k_audit, canonical_json ‖ prev_hash)`, one chain per
 * organisation, insert-only for the application.
 *
 * 🛑 §8.22.4 requires the mutation and its audit row to **commit in one
 * transaction**. This class does not open one for you when you are already in
 * one, so the correct shape at a call site is:
 *
 *     DB::transaction(function () use ($project) {
 *         $project->update(['visibility' => AccessLevel::Public]);
 *         Audit::record(
 *             action: 'project.visibility.changed',
 *             organisationId: $project->organisation_id,
 *             actorType: ActorType::User,
 *             actorId: $actorId,
 *             subjectType: 'project',
 *             subjectId: $project->id,
 *             payload: ['from' => 'members', 'to' => 'public'],
 *         );
 *     });
 *
 * An audit row that commits while its mutation rolls back is a lie, and a
 * mutation that commits while its audit row rolls back is an untracked change.
 * One transaction is the only arrangement where neither can happen.
 */
final class Audit
{
    /**
     * How long to wait for the per-chain lock, in seconds.
     *
     * Short on purpose. The lock is held for one insert, so contention means
     * something is wrong — a long-running transaction holding it, most likely —
     * and failing fast surfaces that instead of stalling every audited action
     * behind it.
     */
    private const LOCK_TIMEOUT_SECONDS = 5;

    /**
     * Record one event and return its id.
     *
     * @param  string  $action  a stable dotted event name, never free text
     * @param  string|null  $organisationId  raw 16 bytes; null for installation-scope events
     * @param  string|null  $actorId  raw 16 bytes; null when the actor is the system
     * @param  array<array-key, mixed>  $payload  🛑 §8.22.5: identifiers, codes and
     *                                            references only. Never a name, an
     *                                            email address or anything erasure
     *                                            would have to remove — it is hashed,
     *                                            so it can never be changed again.
     *
     * @throws AuditKeyMissing when DOCUP_AUDIT_KEY is not configured
     * @throws ChainLockUnavailable when the chain lock cannot be taken
     */
    public static function record(
        string $action,
        ActorType $actorType,
        ?string $organisationId = null,
        ?string $actorId = null,
        ?string $subjectType = null,
        ?string $subjectId = null,
        ?string $reasonCode = null,
        ?string $ruleId = null,
        array $payload = [],
    ): string {
        $key = self::key();
        $chainKey = $organisationId ?? str_repeat("\x00", 16);

        /*
         * 🛑 One writer per chain at a time.
         *
         * Without this, two concurrent events read the same chain head, both
         * compute the same `prev_hash` and the chain FORKS. The damage is
         * subtle and bad: verification then reports a broken chain, so a
         * harmless race presents exactly like tampering — and an operator who
         * has learned that `audit:verify` cries wolf is an operator who will
         * ignore it when it is right.
         *
         * A MySQL advisory lock rather than `SELECT … FOR UPDATE`, because the
         * row to lock does not exist for the first event in a chain and a gap
         * lock is not a guarantee. Named per chain, so chains never block each
         * other.
         */
        $lockName = 'docup:audit:chain:'.bin2hex($chainKey);

        /** @var int|null $acquired */
        $acquired = DB::selectOne(
            'SELECT GET_LOCK(?, ?) AS acquired',
            [$lockName, self::LOCK_TIMEOUT_SECONDS],
        )?->acquired;

        if ($acquired !== 1) {
            throw ChainLockUnavailable::for($chainKey, self::LOCK_TIMEOUT_SECONDS);
        }

        try {
            $head = DB::selectOne(
                'SELECT `sequence`, `hash`
                   FROM `audit_events`
                  WHERE `chain_key` = ?
                  ORDER BY `sequence` DESC
                  LIMIT 1',
                [$chainKey],
            );

            /** @var int $sequence */
            $sequence = $head === null ? 1 : ((int) $head->sequence) + 1;
            /** @var string|null $previousHash */
            $previousHash = $head === null ? null : $head->hash;

            $id = Uuid::v7();
            $occurredAt = now()->format('Y-m-d H:i:s.v');
            $payloadJson = CanonicalJson::encode($payload);

            $canonical = self::canonicalEvent([
                'action' => $action,
                'actor_id' => $actorId === null ? null : bin2hex($actorId),
                'actor_type' => $actorType->value,
                'chain_key' => bin2hex($chainKey),
                'id' => bin2hex($id),
                'occurred_at' => $occurredAt,
                'organisation_id' => $organisationId === null ? null : bin2hex($organisationId),
                'payload_json' => $payloadJson,
                'reason_code' => $reasonCode,
                'rule_id' => $ruleId === null ? null : bin2hex($ruleId),
                'sequence' => $sequence,
                'subject_id' => $subjectId === null ? null : bin2hex($subjectId),
                'subject_type' => $subjectType,
            ]);

            $hash = self::chainHash($canonical, $previousHash, $key);

            DB::insert(
                'INSERT INTO `audit_events`
                    (`id`, `occurred_at`, `organisation_id`, `sequence`, `actor_id`, `actor_type`,
                     `action`, `subject_type`, `subject_id`, `reason_code`, `rule_id`, `payload`,
                     `prev_hash`, `hash`)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    $id, $occurredAt, $organisationId, $sequence, $actorId, $actorType->value,
                    $action, $subjectType, $subjectId, $reasonCode, $ruleId, $payloadJson,
                    $previousHash, $hash,
                ],
            );

            return $id;
        } finally {
            // Released even on failure. An advisory lock survives a rolled-back
            // transaction and is scoped to the connection, so leaking one would
            // block that chain for the life of the connection — which, with a
            // pooled or long-lived worker, means indefinitely.
            DB::selectOne('SELECT RELEASE_LOCK(?) AS released', [$lockName]);
        }
    }

    /**
     * 🛑 The hashed representation of one event. Written and verified from
     * here, and nowhere else.
     *
     * Two things about this are load-bearing.
     *
     * **Every column is covered.** The hash is computed over the event's
     * *fields*, not over a stored blob, and `docup:audit:verify` rebuilds this
     * from the row's columns. An earlier draft of this class hashed a canonical
     * blob and stored that blob in the `payload` column — which meant an
     * attacker could edit `action`, `actor_id` or `occurred_at` in the row and
     * verification would still pass, because the bytes being hashed had not
     * changed. The visible row would say one thing and the chain would vouch
     * for another. Hashing the fields is what makes every column tamper-evident.
     *
     * **The payload travels as a string.** It is pre-encoded by
     * {@see CanonicalJson::encode()} and embedded here as an opaque scalar, so
     * the verifier can take the stored column verbatim rather than decoding and
     * re-encoding it and hoping the round trip is byte-identical.
     *
     * @param  array<string, string|int|null>  $fields
     *
     * @throws \JsonException
     */
    public static function canonicalEvent(array $fields): string
    {
        return CanonicalJson::encode($fields);
    }

    /**
     * 🛑 The chain hash. The one place this is computed.
     *
     * `prev_hash` is appended **raw**, not hex-encoded, and the first event in
     * a chain appends nothing. Both choices are arbitrary but they are now part
     * of the format: `docup:audit:verify` recomputes with this same method, and
     * any divergence between writer and verifier reads as universal tampering.
     * That is why verification calls this rather than reimplementing it.
     */
    public static function chainHash(string $canonicalJson, ?string $previousHash, string $key): string
    {
        return hash_hmac('sha256', $canonicalJson.($previousHash ?? ''), $key, binary: true);
    }

    /**
     * Sign an anchor's head hash (§8.22.1).
     *
     * Domain-separated from {@see self::chainHash()} by the `anchor:` prefix,
     * so an event hash can never be replayed as an anchor signature or the
     * reverse. Using one key for two purposes without separation is how a
     * signature scheme becomes forgeable by its own outputs.
     */
    public static function anchorSignature(string $headHash, string $chainKey, string $anchoredOn, string $key): string
    {
        return hash_hmac(
            'sha256',
            'anchor:'.bin2hex($chainKey).':'.$anchoredOn.':'.bin2hex($headHash),
            $key,
            binary: true,
        );
    }

    /**
     * The audit key (§8.22.1), held outside `APP_KEY`.
     *
     * @throws AuditKeyMissing
     */
    public static function key(): string
    {
        $key = config('docup.audit.key');

        if (! is_string($key) || $key === '') {
            throw AuditKeyMissing::notConfigured();
        }

        return $key;
    }

    /** Whether an audit key is configured at all, for `doctor` to report. */
    public static function hasKey(): bool
    {
        $key = config('docup.audit.key');

        return is_string($key) && $key !== '';
    }
}
