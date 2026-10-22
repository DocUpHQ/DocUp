<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Convert every table to `utf8mb4_0900_ai_ci` (§9.1.6).
 *
 * Phase 01 inherited the Laravel skeleton's `utf8mb4_unicode_ci`, which is the
 * MySQL 5.x collation built on UCA 4.0.0 — a Unicode version from 2003. §9.1.6
 * requires `utf8mb4_0900_ai_ci`, MySQL 8's own default.
 *
 * 🛑 The reason this is worth a migration rather than a note: the hazard is not
 * sorting accuracy, it is **mixing**. A join or comparison between a
 * `utf8mb4_0900_ai_ci` column and a `utf8mb4_unicode_ci` one fails outright
 * with "Illegal mix of collations (…) for operation '='". Once `config/database.php`
 * emits the correct collation, every new table gets it and every table created
 * before this point does not — so a half-converted schema does not sort
 * oddly, it throws on the first query that spans the boundary.
 *
 * Deliberately dated **before** the Phase 02 tables so a fresh install converts
 * the Phase 01 schema and then creates everything else already correct. On an
 * existing installation this runs once over small tables; the same conversion
 * on a grown `audit_events` would hold a lock for a long time, which is the
 * other reason not to defer it.
 *
 * §9.1.6's exception — hostnames as `VARCHAR(253) CHARACTER SET ascii COLLATE
 * ascii_bin` — has no columns yet. Those arrive with domains in Phase 10 and
 * must be declared explicitly there, because this conversion would otherwise
 * sweep them into utf8mb4.
 */
return new class extends Migration
{
    private const TARGET_CHARSET = 'utf8mb4';

    private const TARGET_COLLATION = 'utf8mb4_0900_ai_ci';

    public function up(): void
    {
        $database = (string) DB::connection()->getDatabaseName();

        // MariaDB has no 0900 collations at all, so converting would fail with
        // an unknown-collation error rather than doing something subtly wrong.
        // §11.1 specifies MySQL 8.4; this guard makes the dependency explicit
        // instead of letting it surface as a confusing migration failure.
        if (! $this->supportsTargetCollation()) {
            throw new RuntimeException(
                'This server does not support '.self::TARGET_COLLATION
                .'. SPEC 11.1 requires MySQL 8.4 LTS; MariaDB is not a supported substitute.'
            );
        }

        // The database default too, so a table created by anything that does
        // not go through Laravel's connection config still lands correctly.
        DB::statement(sprintf(
            'ALTER DATABASE `%s` CHARACTER SET = %s COLLATE = %s',
            $database,
            self::TARGET_CHARSET,
            self::TARGET_COLLATION,
        ));

        foreach ($this->tablesToConvert($database) as $table) {
            // CONVERT TO rewrites the columns, not just the table default.
            // `ALTER TABLE … COLLATE =` alone changes what new columns inherit
            // and leaves existing ones on the old collation, which is exactly
            // the half-converted state this migration exists to avoid.
            DB::statement(sprintf(
                'ALTER TABLE `%s` CONVERT TO CHARACTER SET %s COLLATE %s',
                $table,
                self::TARGET_CHARSET,
                self::TARGET_COLLATION,
            ));
        }
    }

    public function down(): void
    {
        // Deliberately not reverted. Going back would re-introduce the mixing
        // hazard above, and no later migration depends on the old collation.
    }

    private function supportsTargetCollation(): bool
    {
        /** @var list<object{Collation?: string}> $rows */
        $rows = DB::select('SHOW COLLATION WHERE Collation = ?', [self::TARGET_COLLATION]);

        return $rows !== [];
    }

    /**
     * Every base table in this schema that is not already converted.
     *
     * `migrations` is included on purpose: it is Laravel's own table, it holds
     * strings, and a join against it is unlikely but a mixed-collation schema
     * is worth eliminating completely rather than nearly.
     *
     * @return list<string>
     */
    private function tablesToConvert(string $database): array
    {
        /** @var list<object{TABLE_NAME: string}> $rows */
        $rows = DB::select(
            'SELECT TABLE_NAME
               FROM information_schema.TABLES
              WHERE TABLE_SCHEMA = ?
                AND TABLE_TYPE = ?
                AND (TABLE_COLLATION IS NULL OR TABLE_COLLATION <> ?)
              ORDER BY TABLE_NAME',
            [$database, 'BASE TABLE', self::TARGET_COLLATION],
        );

        return array_map(static fn (object $row): string => (string) $row->TABLE_NAME, $rows);
    }
};
