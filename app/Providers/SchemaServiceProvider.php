<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Providers;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\ServiceProvider;

/**
 * Schema macros for the SPEC 9.1 identifier policy.
 *
 * Every migration in the project uses these rather than hand-rolling the column
 * definitions, so the policy is applied by construction instead of by review.
 */
final class SchemaServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        /**
         * The primary key: BINARY(16) holding a UUIDv7, plus the SPEC 9.1.2
         * `id_text` virtual column so a human reading phpMyAdmin sees something
         * legible. VIRTUAL costs no storage - it is computed on read.
         */
        Blueprint::macro('uuidKey', function (string $column = 'id'): void {
            /** @var Blueprint $this */
            $this->binary($column, 16, true)->primary();
            $this->string($column.'_text', 36)
                ->virtualAs("BIN_TO_UUID({$column})")
                ->nullable();
        });

        /**
         * A UUID foreign key. BINARY(16) to match, and indexed by default
         * because SPEC 9.1.1 applies to foreign keys as well as primary keys.
         *
         * No `id_text` companion: one legible column per row is enough, and a
         * virtual column per foreign key would triple the read cost of a wide
         * table for no operator benefit.
         */
        Blueprint::macro('uuidForeign', function (string $column, bool $nullable = false, bool $index = true): void {
            /** @var Blueprint $this */
            $definition = $this->binary($column, 16, true);

            if ($nullable) {
                $definition->nullable();
            }

            if ($index) {
                $this->index($column);
            }
        });

        /**
         * A security token column.
         *
         * 🛑 SPEC 9.1.4: tokens are CSPRNG bytes stored as a SHA-256 hash, never
         * UUIDv7, because v7 embeds a readable creation timestamp and these
         * values are enumerable. The indexed prefix lets a lookup find the
         * candidate row without scanning, while the comparison stays on the
         * full hash.
         */
        Blueprint::macro('tokenHash', function (string $column = 'token_hash'): void {
            /** @var Blueprint $this */
            $this->char($column, 64);
            $this->string($column.'_prefix', 12)->index();
        });
    }
}
