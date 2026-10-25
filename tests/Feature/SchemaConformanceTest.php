<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * §9.1 schema rules that are properties of the live schema rather than of the
 * source, so an architecture test scanning files cannot see them.
 *
 * These run against real MySQL by necessity: collation, generated columns and
 * partitioning are server concepts, and a portable assertion about them would
 * be an assertion about nothing.
 */
final class SchemaConformanceTest extends TestCase
{
    private const REQUIRED_COLLATION = 'utf8mb4_0900_ai_ci';

    /**
     * §9.1.6 permits exactly one exception: hostnames are
     * `VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin`, because host
     * comparison is byte-exact and case-folding a hostname under a Unicode
     * collation is how two different hosts come to look like one.
     *
     * Those columns arrive with domains in Phase 10. Listed here now so the
     * exception is explicit when they land rather than being added as a
     * convenient loosening at the time.
     */
    private const ASCII_BIN_ALLOWED = [
        'ascii_bin',
    ];

    /**
     * 🛑 Every table on the required collation.
     *
     * The hazard this guards is not sorting accuracy. A comparison between a
     * `utf8mb4_0900_ai_ci` column and a `utf8mb4_unicode_ci` one fails with
     * "Illegal mix of collations", so a schema that is half converted does not
     * behave slightly differently — it throws on the first query spanning the
     * boundary. Phase 01 shipped entirely on the skeleton's
     * `utf8mb4_unicode_ci`, which is why this test exists.
     */
    public function test_every_table_uses_the_required_collation(): void
    {
        $database = (string) DB::connection()->getDatabaseName();

        /** @var list<object{TABLE_NAME: string, TABLE_COLLATION: string|null}> $rows */
        $rows = DB::select(
            'SELECT TABLE_NAME, TABLE_COLLATION
               FROM information_schema.TABLES
              WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = ?
              ORDER BY TABLE_NAME',
            [$database, 'BASE TABLE'],
        );

        $this->assertNotEmpty($rows, 'no tables found; has the test database been migrated?');

        $wrong = [];

        foreach ($rows as $row) {
            if ($row->TABLE_COLLATION !== self::REQUIRED_COLLATION) {
                $wrong[] = $row->TABLE_NAME.' ('.($row->TABLE_COLLATION ?? 'null').')';
            }
        }

        $this->assertSame(
            [],
            $wrong,
            'these tables are not on '.self::REQUIRED_COLLATION.' (§9.1.6): '.implode(', ', $wrong)
        );
    }

    /**
     * And every string column, which the table default does not guarantee:
     * `ALTER TABLE … COLLATE =` changes what new columns inherit and leaves
     * existing ones alone, so a table can report the right collation while its
     * columns disagree.
     */
    public function test_every_string_column_uses_the_required_collation(): void
    {
        $database = (string) DB::connection()->getDatabaseName();

        /** @var list<object{TABLE_NAME: string, COLUMN_NAME: string, COLLATION_NAME: string}> $rows */
        $rows = DB::select(
            'SELECT TABLE_NAME, COLUMN_NAME, COLLATION_NAME
               FROM information_schema.COLUMNS
              WHERE TABLE_SCHEMA = ?
                AND COLLATION_NAME IS NOT NULL
                AND COLLATION_NAME <> ?
              ORDER BY TABLE_NAME, COLUMN_NAME',
            [$database, self::REQUIRED_COLLATION],
        );

        $wrong = [];

        foreach ($rows as $row) {
            if (in_array($row->COLLATION_NAME, self::ASCII_BIN_ALLOWED, true)) {
                continue;
            }

            $wrong[] = $row->TABLE_NAME.'.'.$row->COLUMN_NAME.' ('.$row->COLLATION_NAME.')';
        }

        $this->assertSame(
            [],
            $wrong,
            'these columns are not on '.self::REQUIRED_COLLATION.' (§9.1.6): '.implode(', ', $wrong)
        );
    }

    /**
     * §9.1.1 applies to foreign keys as well as primary keys, and a mismatched
     * key width is the kind of thing that works until the table grows: MySQL
     * will not use an index when it has to convert the value, so the join
     * degrades to a scan rather than failing.
     */
    public function test_every_id_column_is_binary_16(): void
    {
        $database = (string) DB::connection()->getDatabaseName();

        /** @var list<object{TABLE_NAME: string, COLUMN_NAME: string, DATA_TYPE: string, CHARACTER_MAXIMUM_LENGTH: int|null}> $rows */
        $rows = DB::select(
            "SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH
               FROM information_schema.COLUMNS
              WHERE TABLE_SCHEMA = ?
                AND (COLUMN_NAME = 'id' OR COLUMN_NAME LIKE '%\\_id')
              ORDER BY TABLE_NAME, COLUMN_NAME",
            [$database],
        );

        $this->assertNotEmpty($rows);

        // Framework-owned tables keep their own key shapes: §9.1.3 allowlists
        // the queue tables' AUTO_INCREMENT by name for the same reason, and
        // Laravel's queue driver reads those integer keys directly.
        $frameworkTables = ['jobs', 'job_batches', 'failed_jobs', 'migrations', 'sessions'];

        /*
         * 🛑 Columns that end in `_id` and are **not DocUp identifiers**.
         *
         * §9.1.1 governs "every primary and foreign key" — the keys DocUp
         * issues, where UUIDv7's time ordering is the index-locality property
         * the whole decision rests on (ADR 0006). A column holding a *foreign
         * system's* identifier is data, not a key: ADR 0009 verified that the
         * five providers of §8.3.1 issue an `int64` or a braced UUIDv4, so
         * `BINARY(16)` is not merely inconvenient here but impossible, and the
         * locality argument does not apply to a value we did not mint.
         *
         * Exempted by exact `table.column`, never by pattern, so adding one is
         * a visible act with a reviewer. The matching rule is deliberately
         * crude and this list is deliberately short: if it ever grows past a
         * handful, the question to ask is whether the naming convention is
         * wrong rather than whether the test is.
         */
        $foreignIdentifierColumns = [
            'repositories.provider_repo_id',    // §18.27 / ADR 0009: the provider's own id
            'build_requests.delivery_id',       // §8.5.4: the provider's own webhook delivery id
            // Phase 11, and the same column for the same reason one table
            // along: §8.19.3's replay ledger is keyed on whatever the
            // provider calls its delivery, and the five of §8.3.1 do not
            // agree — GitHub sends a UUIDv4 string, Bitbucket a braced one,
            // Gitea an opaque token. Storing it as BINARY(16) would mean
            // parsing a foreign system's identifier before we are allowed
            // to remember we have seen it, and failing to parse would mean
            // failing to detect a replay.
            'incoming_webhook_deliveries.delivery_id',
        ];

        $wrong = [];

        foreach ($rows as $row) {
            if (in_array($row->TABLE_NAME, $frameworkTables, true)) {
                continue;
            }

            if (in_array($row->TABLE_NAME.'.'.$row->COLUMN_NAME, $foreignIdentifierColumns, true)) {
                continue;
            }

            if ($row->DATA_TYPE !== 'binary' || $row->CHARACTER_MAXIMUM_LENGTH !== 16) {
                $wrong[] = sprintf(
                    '%s.%s (%s%s)',
                    $row->TABLE_NAME,
                    $row->COLUMN_NAME,
                    $row->DATA_TYPE,
                    $row->CHARACTER_MAXIMUM_LENGTH === null ? '' : '('.$row->CHARACTER_MAXIMUM_LENGTH.')',
                );
            }
        }

        $this->assertSame(
            [],
            $wrong,
            'these identifier columns are not BINARY(16) (§9.1.1): '.implode(', ', $wrong)
        );
    }
}
