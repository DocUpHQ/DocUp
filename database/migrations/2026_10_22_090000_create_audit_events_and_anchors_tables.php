<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * The tamper-evident dashboard audit log (§8.22.1, §8.22.5, §10.6, §20.3).
 *
 * Raw DDL rather than the schema builder, because Laravel cannot express
 * partitioning and this table's shape is forced by it.
 *
 * 🛑 **Three MySQL facts drive every oddity below**, and they are worth stating
 * once here rather than being rediscovered:
 *
 * 1. A partitioned InnoDB table **cannot carry foreign keys at all**. §10.6
 *    says so and MySQL enforces it. Hence the denormalised, FK-free columns.
 * 2. Every unique key on a partitioned table **must include the partitioning
 *    column**. So the primary key is `(id, occurred_at)`, not `id`.
 * 3. Point 2 collides with chain integrity. The natural constraint is
 *    `UNIQUE (chain_key, sequence)` — one position per chain — but that is
 *    illegal here unless `occurred_at` joins it, which weakens it to "one
 *    position per chain per instant". **The hash chain is what closes that
 *    gap**: a duplicated sequence cannot also produce a valid `prev_hash`
 *    linkage, so `docup:audit:verify` detects it even though the index cannot
 *    prevent it. The specification requires both partitioning and chaining, and
 *    this is how both hold — the index is a convenience, the chain is the
 *    integrity mechanism.
 *
 * 🛑 §8.22.5 is the rule that shapes the payload: the chain hashes **only
 * opaque identifiers**. Human-readable labels live in the mutable
 * `actor_labels` table. Denormalising a name in here would make "erasure
 * removes all personal data" and "the chain still verifies" mutually
 * exclusive — satisfiable either way but never both, and the trade would be
 * discovered in Phase 35 with the log already written.
 */
return new class extends Migration
{
    /**
     * Months of partitions created up front.
     *
     * The scheduled maintenance principal (§8.22.1) adds more. This is enough
     * runway that a installation which never runs maintenance still writes into
     * a real partition for over a year rather than piling into `pmax`.
     */
    private const MONTHS_AHEAD = 14;

    public function up(): void
    {
        DB::statement($this->auditEventsDdl());

        Schema::create('audit_anchors', function (Blueprint $table): void {
            $table->uuidKey();

            /*
             * The chain this anchor pins. COALESCE of organisation_id, matching
             * audit_events, so installation-scope events form their own chain
             * rather than being mixed into an arbitrary organisation's.
             */
            $table->binary('chain_key', 16, true);

            $table->date('anchored_on');

            // The last event in the chain as at the end of that day.
            $table->binary('head_hash', 32, true);
            $table->unsignedBigInteger('head_sequence');
            $table->unsignedBigInteger('event_count');

            /*
             * 🛑 §8.22.1: anchors are **signed**. The signature covers the head
             * hash, so an attacker who rewrites history and recomputes every
             * event hash still cannot produce a matching anchor without
             * `k_audit`. Without this, a chain is only tamper-evident against
             * someone who lacks the ability to recompute it — which is to say,
             * against almost nobody who has write access to the database.
             */
            $table->binary('signature', 32, true);

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique(['chain_key', 'anchored_on']);
        });

        DataClassification::annotate('audit_events', [
            ['id', 'operational', 'not_applicable', 'audit_events', null],
            ['id_text', 'derived', 'not_applicable', 'audit_events', 'generated view of id'],
            ['occurred_at', 'operational', 'not_applicable', 'audit_events', 'the partition key'],
            ['organisation_id', 'operational', 'not_applicable', 'audit_events', 'no FK: partitioned InnoDB cannot carry one'],
            ['chain_key', 'derived', 'not_applicable', 'audit_events', 'COALESCE of organisation_id; one chain per tenant'],
            ['sequence', 'operational', 'not_applicable', 'audit_events', 'position in the chain'],
            // 🛑 Opaque on purpose. The readable label lives in actor_labels,
            // which erasure tombstones without touching this.
            ['actor_id', 'pseudonymous', 'not_applicable', 'audit_events', '🛑 §8.22.5 opaque; label lives in actor_labels and is erased there'],
            ['actor_type', 'operational', 'not_applicable', 'audit_events', null],
            ['action', 'operational', 'not_applicable', 'audit_events', null],
            ['subject_type', 'operational', 'not_applicable', 'audit_events', null],
            ['subject_id', 'pseudonymous', 'not_applicable', 'audit_events', '🛑 §8.22.5 opaque reference only'],
            ['reason_code', 'operational', 'not_applicable', 'audit_events', 'stable code, never free text'],
            ['rule_id', 'operational', 'not_applicable', 'audit_events', null],
            ['payload', 'pseudonymous', 'not_applicable', 'audit_events', '🛑 §8.22.5 identifiers only; never names or addresses'],
            ['prev_hash', 'operational', 'not_applicable', 'audit_events', 'the chain link'],
            ['hash', 'operational', 'not_applicable', 'audit_events', 'HMAC(k_audit, canonical_json ‖ prev_hash)'],
        ]);

        DataClassification::annotate('audit_anchors', [
            ['id', 'operational', 'not_applicable', 'audit_anchors', null],
            ['id_text', 'derived', 'not_applicable', 'audit_anchors', 'generated view of id'],
            ['chain_key', 'operational', 'not_applicable', 'audit_anchors', null],
            ['anchored_on', 'operational', 'not_applicable', 'audit_anchors', null],
            ['head_hash', 'operational', 'not_applicable', 'audit_anchors', null],
            ['head_sequence', 'operational', 'not_applicable', 'audit_anchors', null],
            ['event_count', 'operational', 'not_applicable', 'audit_anchors', null],
            ['signature', 'secret', 'not_applicable', 'audit_anchors', 'HMAC over the head hash; forgery needs k_audit'],
            ['created_at', 'operational', 'not_applicable', 'audit_anchors', null],
            ['updated_at', 'operational', 'not_applicable', 'audit_anchors', null],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('audit_anchors');
        Schema::dropIfExists('audit_events');

        DataClassification::forget('audit_anchors');
        DataClassification::forget('audit_events');
    }

    private function auditEventsDdl(): string
    {
        return sprintf(
            <<<'SQL'
            CREATE TABLE `audit_events` (
              `id`              BINARY(16)      NOT NULL,
              `id_text`         CHAR(36)        AS (BIN_TO_UUID(`id`)) VIRTUAL,
              `occurred_at`     DATETIME(3)     NOT NULL,
              `organisation_id` BINARY(16)      NULL,
              `chain_key`       BINARY(16)      AS (COALESCE(`organisation_id`, UNHEX(REPEAT('0', 32)))) STORED NOT NULL,
              `sequence`        BIGINT UNSIGNED NOT NULL,
              `actor_id`        BINARY(16)      NULL,
              `actor_type`      ENUM('user', 'api_token', 'group', 'system') NOT NULL,
              `action`          VARCHAR(96)     NOT NULL,
              `subject_type`    VARCHAR(64)     NULL,
              `subject_id`      BINARY(16)      NULL,
              `reason_code`     VARCHAR(64)     NULL,
              `rule_id`         BINARY(16)      NULL,
              `payload`         JSON            NOT NULL,
              `prev_hash`       BINARY(32)      NULL,
              `hash`            BINARY(32)      NOT NULL,
              PRIMARY KEY (`id`, `occurred_at`),
              UNIQUE KEY `audit_events_chain_position_unique` (`chain_key`, `sequence`, `occurred_at`),
              KEY `audit_events_chain_seq_index` (`chain_key`, `sequence`),
              KEY `audit_events_actor_index` (`actor_id`),
              KEY `audit_events_subject_index` (`subject_type`, `subject_id`),
              KEY `audit_events_action_index` (`action`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
            PARTITION BY RANGE COLUMNS(`occurred_at`) (
            %s
            )
            SQL,
            $this->partitionList(),
        );
    }

    /**
     * Monthly partitions, plus the catch-all §16 requires.
     *
     * 🛑 `pmax` is not optional and is not a tidy default. Without a
     * `MAXVALUE` partition, an insert whose `occurred_at` falls past the last
     * defined boundary **fails** — so the day monthly maintenance stops running
     * is the day every audited action starts erroring, and §8.22.4 commits the
     * audit row in the same transaction as the mutation. The whole dashboard
     * would stop accepting writes. The catch-all converts that outage into a
     * degradation (one fat partition) which §16 pairs with alerting.
     */
    private function partitionList(): string
    {
        $partitions = [];
        $month = Carbon::now('UTC')->startOfMonth();

        for ($i = 0; $i < self::MONTHS_AHEAD; $i++) {
            $boundary = $month->copy()->addMonth();

            $partitions[] = sprintf(
                "  PARTITION `p%s` VALUES LESS THAN ('%s')",
                $month->format('Y_m'),
                $boundary->format('Y-m-d'),
            );

            $month = $boundary;
        }

        $partitions[] = '  PARTITION `pmax` VALUES LESS THAN (MAXVALUE)';

        return implode(",\n", $partitions);
    }
};
