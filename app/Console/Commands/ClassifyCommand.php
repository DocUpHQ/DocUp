<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

/**
 * `docup:classify` - the data-classification coverage check (SPEC 8.22.7).
 *
 * 🛑 Every column in the database carries a classification, CI fails when an
 * unclassified column is introduced, and the subject-access export and erasure
 * commands are verified complete against this register.
 *
 * That chain is what makes the SPEC 8.22.9 erasure promise PROVABLE instead of
 * asserted. Without it, `docup:erase` is a function somebody extended by hand
 * every time the schema grew, and the first column they forgot is the one that
 * matters.
 *
 * Phase 01 ships the register and this check. Phase 35 adds the export and
 * erasure commands that consume it.
 */
final class ClassifyCommand extends Command
{
    protected $signature = 'docup:classify
        {--check : Exit non-zero if any column is unclassified}
        {--json : Machine-readable output}';

    protected $description = 'Check that every database column carries a data classification (SPEC 8.22.7)';

    /**
     * Tables the register does not govern.
     *
     * Framework-owned plumbing, not DocUp's data model. Each is named
     * explicitly rather than matched by a pattern, so adding one is a visible
     * decision - the same discipline SPEC 9.1.3 applies to the AUTO_INCREMENT
     * allowlist.
     *
     * @var list<string>
     */
    private const UNGOVERNED = [
        'migrations',
        'cache',
        'cache_locks',
        'jobs',
        'job_batches',
        'failed_jobs',
        'data_class_annotations',   // the register does not classify itself
    ];

    public function handle(): int
    {
        $database = (string) DB::connection()->getDatabaseName();

        /** @var list<object{TABLE_NAME: string, COLUMN_NAME: string}> $columns */
        $columns = DB::select(
            'SELECT TABLE_NAME, COLUMN_NAME
               FROM information_schema.COLUMNS
              WHERE TABLE_SCHEMA = ?
              ORDER BY TABLE_NAME, ORDINAL_POSITION',
            [$database],
        );

        /** @var list<object{table_name: string, column_name: string}> $classified */
        $classified = DB::table('data_class_annotations')
            ->select('table_name', 'column_name')
            ->get()
            ->all();

        $known = [];

        foreach ($classified as $row) {
            $known[$row->table_name.'.'.$row->column_name] = true;
        }

        $missing = [];
        $governed = 0;

        foreach ($columns as $column) {
            /** @var string $table */
            $table = $column->TABLE_NAME;
            /** @var string $name */
            $name = $column->COLUMN_NAME;

            if (in_array($table, self::UNGOVERNED, true)) {
                continue;
            }

            // The SPEC 9.1.2 id_text virtual column is a derived view of the
            // key, not a separate fact about a person, so it inherits the key's
            // classification rather than needing its own row.
            if (str_ends_with($name, '_text') && isset($known[$table.'.'.substr($name, 0, -5)])) {
                continue;
            }

            $governed++;

            if (! isset($known[$table.'.'.$name])) {
                $missing[] = $table.'.'.$name;
            }
        }

        if ($this->option('json')) {
            $this->line((string) json_encode([
                'governed' => $governed,
                'classified' => $governed - count($missing),
                'missing' => $missing,
            ], JSON_PRETTY_PRINT));
        } else {
            $this->newLine();
            $this->line(sprintf(
                '  %d of %d governed columns classified.',
                $governed - count($missing),
                $governed,
            ));

            if ($missing !== []) {
                $this->newLine();
                $this->line('  <fg=red>Unclassified columns (SPEC 8.22.7):</>');

                foreach ($missing as $column) {
                    $this->line("    - {$column}");
                }

                $this->newLine();
                $this->line('  <fg=gray>Add a row to data_class_annotations for each. A column with no</>');
                $this->line('  <fg=gray>classification cannot be covered by DSAR export or erasure, and the</>');
                $this->line('  <fg=gray>first one forgotten is the one that matters.</>');
            }

            $this->newLine();
        }

        if ($missing !== [] && $this->option('check')) {
            return self::FAILURE;
        }

        return self::SUCCESS;
    }
}
