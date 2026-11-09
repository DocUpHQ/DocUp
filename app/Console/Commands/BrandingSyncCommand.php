<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Branding\BrandingToken;
use App\Branding\TokenRegistry;
use App\Models\TokenDefinition;
use App\Support\Uuid;
use Illuminate\Console\Command;

/**
 * `docup:branding-sync` — write §8.14.1's registry into §10.7's
 * `token_definitions`.
 *
 * ## 🛑 The table is a record, never an authority
 *
 * {@see TokenRegistry} validates. This command makes what the installation
 * defines queryable without booting every plugin, which is what §8.14.1's
 * "plugin-extendable" costs: the set an installation holds depends on which
 * plugins are installed, so "what does *this* installation define" is a
 * question only the installation can answer and only if somebody wrote it
 * down.
 *
 * ## 🛑 `--check` is the half CI runs
 *
 * {@see RenderDocsCommand} says why about the generated documentation blocks,
 * and the argument is the same: a generator nobody verifies is a generator
 * somebody forgets to run. Here the consequence is narrower and worth stating
 * — a stale table makes `docup doctor` report the wrong token set, which is
 * exactly the kind of wrong that reads as right.
 *
 * ## 🛑 A plugin's rows are never pruned
 *
 * A `core` row the registry no longer defines is deleted; a `plugin` row is
 * left alone. Uninstalling a plugin must not silently drop a definition some
 * tenant's theme still references — that is a `doctor` finding, which is job
 * (2) of the three the migration lists.
 */
final class BrandingSyncCommand extends Command
{
    protected $signature = 'docup:branding-sync
        {--check : Exit non-zero if the table disagrees with the registry}';

    protected $description = 'Record §8.14.1’s token registry in token_definitions (§10.7)';

    public function handle(): int
    {
        $expected = [];

        foreach (TokenRegistry::all() as $name => $token) {
            $expected[$name] = self::rowFor($token);
        }

        /** @var array<string, TokenDefinition> $existing */
        $existing = TokenDefinition::query()->get()->keyBy('name')->all();

        $stale = [];
        $rows = [];

        foreach ($expected as $name => $attributes) {
            $row = $existing[$name] ?? null;

            if ($row === null) {
                $stale[] = $name.' is missing';
                $rows[] = ['id' => Uuid::v7(), 'name' => $name, ...$attributes];

                continue;
            }

            if (self::differs($row, $attributes)) {
                $stale[] = $name.' is out of date';
                $rows[] = ['id' => $row->getRawOriginal('id'), 'name' => $name, ...$attributes];
            }
        }

        /*
         * 🛑 Only `core` rows are pruned — see the class docblock. A plugin
         * row whose plugin is gone is a finding, not a tidy-up.
         */
        $orphans = [];

        foreach ($existing as $name => $row) {
            if (! array_key_exists($name, $expected) && $row->source === 'core') {
                $orphans[] = $name;
                $stale[] = $name.' is no longer defined';
            }
        }

        if ($this->option('check')) {
            if ($stale === []) {
                $this->components->info(count($expected).' token definitions recorded and current.');

                return self::SUCCESS;
            }

            foreach ($stale as $message) {
                $this->components->twoColumnDetail($message, '<fg=red>stale</>');
            }

            $this->components->error('run php artisan docup:branding-sync');

            return self::FAILURE;
        }

        if ($rows !== []) {
            /*
             * Upserted on `name`, which is the table's unique key, so a
             * re-run is idempotent and a changed default is one statement
             * rather than a read-modify-write per token.
             */
            TokenDefinition::query()->upsert(
                $rows,
                ['name'],
                array_keys(self::rowFor(TokenRegistry::get('brand.name'))),
            );
        }

        if ($orphans !== []) {
            TokenDefinition::query()->whereIn('name', $orphans)->where('source', 'core')->delete();
        }

        $this->components->info(sprintf(
            '%d token definitions recorded (%d written, %d removed).',
            count($expected),
            count($rows),
            count($orphans),
        ));

        return self::SUCCESS;
    }

    /**
     * One registry entry as a row.
     *
     * @return array<string, mixed>
     */
    private static function rowFor(BrandingToken $token): array
    {
        return [
            'type' => $token->type->value,
            'token_group' => $token->group,
            'default_value' => $token->default,
            'dark_value' => $token->dark,
            'deepest_level' => $token->deepest->value,
            'options' => json_encode($token->options, JSON_THROW_ON_ERROR),
            'minimum' => number_format($token->minimum, 4, '.', ''),
            'maximum' => number_format($token->maximum, 4, '.', ''),
            'max_length' => $token->maxLength,
            'asset_kind' => $token->assetKind,
            'purpose' => $token->purpose,
            'source' => str_starts_with($token->name, TokenRegistry::EXTENSION_PREFIX) ? 'plugin' : 'core',
            'updated_at' => now(),
            'created_at' => now(),
        ];
    }

    /**
     * Whether a stored row disagrees with the registry.
     *
     * 🛑 `created_at` and `updated_at` are excluded, because comparing them
     * would make every row stale on every run — and `--check` would then be a
     * check that always fails, which is a check nobody keeps.
     *
     * @param  array<string, mixed>  $attributes
     */
    private static function differs(TokenDefinition $row, array $attributes): bool
    {
        foreach ($attributes as $column => $value) {
            if ($column === 'created_at' || $column === 'updated_at') {
                continue;
            }

            $stored = $column === 'options'
                ? json_encode($row->options, JSON_THROW_ON_ERROR)
                : $row->getAttribute($column);

            if ((string) $stored !== (string) $value) {
                return true;
            }
        }

        return false;
    }
}
