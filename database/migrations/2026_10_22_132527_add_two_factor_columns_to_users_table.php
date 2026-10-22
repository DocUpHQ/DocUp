<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Fortify's two-factor columns (§8.13.4).
 *
 * Published by `vendor:publish` and then edited, which is deliberate: a
 * migration in this repository is DocUp's, whoever wrote it first. It needs the
 * SPDX header every first-party file carries and the §8.22.7 classification
 * rows, because the CI coverage check does not care where a column came from —
 * and neither does an erasure request.
 */
return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->text('two_factor_secret')
                ->after('password')
                ->nullable();

            $table->text('two_factor_recovery_codes')
                ->after('two_factor_secret')
                ->nullable();

            $table->timestamp('two_factor_confirmed_at')
                ->after('two_factor_recovery_codes')
                ->nullable();
        });

        /*
         * 🛑 §8.22.7: every column carries a classification, and CI fails on an
         * unclassified one — including columns a package published. A vendor
         * migration is not exempt from the erasure promise: `two_factor_secret`
         * is exactly the kind of column that must be known to
         * `docup:erase`, and the register is how that is provable rather than
         * asserted.
         */
        DataClassification::annotate('users', [
            ['two_factor_secret', 'secret', 'platform', null, '🛑 TOTP shared secret; encrypted at rest, never exported'],
            ['two_factor_recovery_codes', 'secret', 'platform', null, '§9.1.4: single-use codes, encrypted'],
            ['two_factor_confirmed_at', 'operational', 'platform', null, 'enrolment is incomplete until a code is verified (§8.13.4)'],
        ]);
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->dropColumn([
                'two_factor_secret',
                'two_factor_recovery_codes',
                'two_factor_confirmed_at',
            ]);
        });
    }
};
