<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Identity columns on `users` that Fortify does not provide (§8.13.3, §8.22.6,
 * §8.22.13).
 *
 * 🛑 **No MFA columns here.** An earlier version of this migration added
 * `mfa_secret`, `mfa_confirmed_at` and `mfa_recovery_codes` — and then Fortify
 * was installed, which brings `two_factor_secret`,
 * `two_factor_recovery_codes` and `two_factor_confirmed_at` and the working
 * TOTP implementation that reads them. Keeping both would have left two places
 * recording whether MFA is enabled, with Fortify writing one and this
 * application's own checks reading the other. "MFA is on" would have been true
 * and false at the same time.
 *
 * So the MFA columns are Fortify's, classified in the migration Fortify
 * published, and this one keeps only what Fortify has no opinion about.
 */
return new class extends Migration
{
    /** @var list<string> */
    private const COLUMNS = ['display_timezone', 'permission_epoch', 'deleted_at'];

    public function up(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            // §8.22.13: a display timezone, defaulting to the organisation's.
            $table->string('display_timezone', 64)->nullable();

            /*
             * 🛑 §8.13.3: "a permission epoch compared on every request".
             *
             * Bumped whenever this user's effective permissions change, so a
             * session carrying a stale epoch is rejected. Without it, revoking
             * a role leaves every already-authenticated session holding it
             * until expiry — up to the full 12 hours §8.13.3 allows. "Access
             * removed" has to mean now, not eventually.
             */
            $table->unsignedBigInteger('permission_epoch')->default(1);

            // §8.22.6: a recovery window, not a state. The mandatory hard purge
            // at 30 days is what makes the erasure promise honest.
            $table->datetime('deleted_at', 3)->nullable()->index();
        });

        DataClassification::annotate('users', [
            ['display_timezone', 'personal', 'platform', null, 'a preference, and a weak location signal'],
            ['permission_epoch', 'operational', 'platform', null, '§8.13.3 compared on every request'],
            ['deleted_at', 'operational', 'platform', null, '§8.22.6 recovery window; hard purge at 30 days'],
        ]);
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->dropColumn(self::COLUMNS);
        });

        foreach (self::COLUMNS as $column) {
            DB::table('data_class_annotations')
                ->where('table_name', 'users')
                ->where('column_name', $column)
                ->delete();
        }
    }
};
