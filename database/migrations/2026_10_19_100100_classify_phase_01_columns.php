<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\Uuid;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Classify the columns Phase 01 creates (SPEC 8.22.7).
 *
 * The register's first real use, and the pattern every later phase follows: a
 * migration that creates columns ships the classification for them in the same
 * migration, so `docup:classify --check` never goes red on main and nobody has
 * to classify a grown schema in one sitting.
 *
 * The `note` on each row is the reason, per SPEC 4.3: a classification whose
 * reason is missing gets changed by someone who cannot see what it protected.
 */
return new class extends Migration
{
    /**
     * @return list<array{0: string, 1: string, 2: string, 3: string, 4: string|null, 5: string|null}>
     */
    private function rows(): array
    {
        return [
            // table, column, classification, erasure, retention class, note
            ['users', 'id', 'pseudonymous', 'platform', null, 'UUIDv7 identifies a person only via this table'],
            ['users', 'name', 'personal', 'platform', null, 'self-supplied display name'],
            ['users', 'email', 'personal', 'platform', null, 'the account identifier and a contact address'],
            ['users', 'email_verified_at', 'operational', 'platform', null, 'a fact about the account, not about the person'],
            ['users', 'password', 'secret', 'platform', null, 'Argon2id hash; never exported, never logged (SPEC 8.12.16)'],
            ['users', 'remember_token', 'secret', 'platform', null, 'session persistence token'],
            ['users', 'created_at', 'operational', 'platform', null, null],
            ['users', 'updated_at', 'operational', 'platform', null, null],

            ['password_reset_tokens', 'email', 'personal', 'platform', null, 'keyed on the address, so the row itself is personal data'],
            ['password_reset_tokens', 'token', 'secret', 'platform', null, 'hashed single-use token'],
            ['password_reset_tokens', 'created_at', 'operational', 'platform', null, 'drives expiry'],

            ['sessions', 'id', 'pseudonymous', 'platform', 'application_logs', 'session identifier'],
            ['sessions', 'user_id', 'pseudonymous', 'platform', 'application_logs', 'links a session to a person'],
            // 🛑 SPEC 8.22.2 keeps raw IPs out of the delivery plane entirely and
            // confines them to security_events with a 7-day retention. These two
            // are Laravel's own dashboard session table, so they are personal
            // data under the platform's control and must be erased with the user.
            ['sessions', 'ip_address', 'personal', 'platform', 'security_events', 'raw IP of a dashboard session'],
            ['sessions', 'user_agent', 'personal', 'platform', 'security_events', 'device fingerprinting surface'],
            ['sessions', 'payload', 'personal', 'platform', 'application_logs', 'may contain anything the session held'],
            ['sessions', 'last_activity', 'operational', 'platform', 'application_logs', null],

            ['data_class_annotations', 'id', 'operational', 'not_applicable', null, 'the register does not classify itself'],
        ];
    }

    public function up(): void
    {
        $now = now();
        $insert = [];

        foreach ($this->rows() as [$table, $column, $classification, $erasure, $retention, $note]) {
            $insert[] = [
                'id' => Uuid::v7(),
                'table_name' => $table,
                'column_name' => $column,
                'classification' => $classification,
                'erasure' => $erasure,
                'retention_class' => $retention,
                'note' => $note,
                'created_at' => $now,
                'updated_at' => $now,
            ];
        }

        DB::table('data_class_annotations')->upsert(
            $insert,
            ['table_name', 'column_name'],
            ['classification', 'erasure', 'retention_class', 'note', 'updated_at'],
        );
    }

    public function down(): void
    {
        foreach ($this->rows() as [$table, $column]) {
            DB::table('data_class_annotations')
                ->where('table_name', $table)
                ->where('column_name', $column)
                ->delete();
        }
    }
};
