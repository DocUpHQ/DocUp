<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * §8.7.12's second composition mode, as a column (§10.4).
 *
 * > "**`single_pass` (opt-in, build-time).** All sources checked out side by
 * > side in **one** sandbox with one toolchain, with **DocUp generating the
 * > playbook or include file from the resolved plan** so a contributing
 * > repository cannot redirect sources or add a fourth repository."
 *
 * §10.4 has listed `merge_policy ∈ {mount,single_pass}` on `projects` since
 * Phase 00 and nothing created it, because nothing could read it until there
 * were two modes. Phase 14 built the first; this is the second.
 *
 * 🛑 **On the project, not the version**, which is what §10.4 says and is
 * the harder of the two to change later. A version-level policy would let
 * `v1` serve a composed site and `v2` serve a mounted one — two different
 * 404 chains, two different cross-reference mechanisms and two different
 * provenance shapes inside one project, which is the ambiguity §8.7.13
 * exists to remove.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('projects', function (Blueprint $table): void {
            /*
             * `mount` by default, because §8.7.12 says so in the same
             * breath as it names the modes: "`mount` (default,
             * serve-time)". The default matters beyond tidiness — every
             * project that exists when this migration runs was composed
             * under `mount`'s rules, and a default of `single_pass` would
             * silently change what each of them serves.
             */
            $table->enum('merge_policy', ['mount', 'single_pass'])
                ->default('mount')
                ->after('preview_fanout_cap');
        });

        DataClassification::annotate('projects', [
            ['merge_policy', 'operational', 'not_applicable', null, '§8.7.12 composition mode; §8.7.13 documents the difference'],
        ]);
    }

    public function down(): void
    {
        if (Schema::hasColumn('projects', 'merge_policy')) {
            Schema::table('projects', function (Blueprint $table): void {
                $table->dropColumn('merge_policy');
            });
        }

        DataClassification::forget('projects', ['merge_policy']);
    }
};
