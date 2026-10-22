<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Support;

use Illuminate\Support\Facades\DB;

/**
 * Writes rows into the §8.22.7 data-classification register.
 *
 * Exists so that a migration creating columns can classify them **in the same
 * migration** without 60 lines of array literal. That rule is the one that
 * keeps `docup:classify --check` green on `main`: classification deferred to a
 * later migration is classification done in one sitting across a grown schema,
 * which is how it ends up rubber-stamped.
 *
 * 🛑 Deliberately thin, and deliberately not a model. A migration is a
 * historical record that must still run years later, so it may only depend on
 * things that do not change shape: this writes to a table with an `upsert` and
 * does nothing else. If this class ever needs a behaviour change, add a new
 * method rather than altering an existing one, because old migrations call it.
 */
final class DataClassification
{
    /**
     * Classify columns for one table.
     *
     * Idempotent, so a re-run of a migration in development does not fail on
     * the unique index. Each row is `[column, classification, erasure,
     * retention_class, note]`, with the last two optional.
     *
     * @param  list<array{0: string, 1: string, 2: string, 3?: string|null, 4?: string|null}>  $columns
     */
    public static function annotate(string $table, array $columns): void
    {
        if ($columns === []) {
            return;
        }

        $now = now();
        $rows = [];

        foreach ($columns as $column) {
            $rows[] = [
                'id' => Uuid::v7(),
                'table_name' => $table,
                'column_name' => $column[0],
                'classification' => $column[1],
                'erasure' => $column[2],
                'retention_class' => $column[3] ?? null,
                'note' => $column[4] ?? null,
                'created_at' => $now,
                'updated_at' => $now,
            ];
        }

        DB::table('data_class_annotations')->upsert(
            $rows,
            ['table_name', 'column_name'],
            ['classification', 'erasure', 'retention_class', 'note', 'updated_at'],
        );
    }

    /**
     * Remove classifications, for a migration's `down()`.
     *
     * A dropped table whose annotations survive makes `classify --check` report
     * coverage for columns that no longer exist, which reads as a pass and is
     * noise at best.
     *
     * 🛑 Pass `$columns` when the migration added columns to an existing table
     * rather than creating it. Without them this deletes every annotation for
     * the table — so a `Schema::table` migration rolling back would silently
     * strip the annotations an earlier migration wrote, and `classify --check`
     * would then fail on columns nobody had touched. The whole-table form is
     * correct only for a migration that also drops the table.
     *
     * @param  list<string>|null  $columns  null means the whole table
     */
    public static function forget(string $table, ?array $columns = null): void
    {
        $query = DB::table('data_class_annotations')->where('table_name', $table);

        if ($columns !== null) {
            $query->whereIn('column_name', $columns);
        }

        $query->delete();
    }
}
