<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The data-classification register (SPEC 8.22.7).
 *
 * 🛑 This table is what makes the erasure and export promises PROVABLE rather
 * than asserted. Every column in the database carries a classification here;
 * CI fails when an unclassified column is introduced; and `docup:dsar:export`
 * and `docup:erase` are verified complete against this register by an automated
 * column-coverage test rather than by someone remembering to extend them.
 *
 * It is created in Phase 01, before any domain model exists, so that the first
 * table anyone adds is already covered by the check. Retrofitting it after the
 * schema has grown would mean classifying the whole schema in one sitting -
 * which is exactly how it ends up rubber-stamped.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('data_class_annotations', function (Blueprint $table): void {
            $table->uuidKey();

            $table->string('table_name', 64);
            $table->string('column_name', 64);

            // What kind of data this column holds. `personal` and `pseudonymous`
            // are the two that drive subject-access export and erasure.
            $table->enum('classification', [
                'personal',       // directly identifies a person
                'pseudonymous',   // identifies a person only with extra data (e.g. a salted hash)
                'operational',    // about the system, not a person
                'content',        // repository-derived documentation content
                'secret',         // credentials and keys; never exported, always encrypted
                'derived',        // computable from other columns; not backed up (SPEC 15.2)
            ]);

            // SPEC 8.22.9: the erasure boundary. `platform` data DocUp erases
            // itself; `content` data is the operator's controller responsibility
            // and gets a tombstone plus a documented rebuild procedure.
            $table->enum('erasure', ['platform', 'content', 'not_applicable'])
                ->default('not_applicable');

            // Which retention class in SPEC 20.3 governs this column.
            $table->string('retention_class', 48)->nullable();

            // Why. SPEC 4.3 "put the reason beside the rule": a classification
            // whose reason is missing gets changed by someone who cannot see
            // what it was protecting.
            $table->string('note', 255)->nullable();

            $table->timestamps();

            $table->unique(['table_name', 'column_name']);
            $table->index('classification');
            $table->index('erasure');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('data_class_annotations');
    }
};
