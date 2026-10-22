<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Per-build chrome injection coverage (§8.15.3, §8.15.4).
 *
 * §8.15.3: "Per-build injection coverage MUST be recorded and reported as a
 * build warning with samples." §8.15.4: "`builds.injector_version` MUST be
 * stamped and a re-ingest job MUST ship."
 *
 * 🛑 On the **build**, not the project, and that is the point of both
 * requirements. Chrome is injected into bytes that are immutable once stored
 * (§8.8.1), so the only honest place to record what was done to them is beside
 * the build that produced them. A project-level flag would say what the project
 * wants; these columns say what each artifact actually got.
 *
 * `injector_version` is what makes the re-ingest job possible at all: when the
 * tags change, there is no way to find the artifacts still carrying the old ones
 * except by asking which version stamped them.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('builds', function (Blueprint $table): void {
            /*
             * 🛑 §8.15.4. Nullable because a build that produced no HTML — a
             * pdf-only output — was never injected into, and recording version
             * 1 for it would make the re-ingest job's query return artifacts
             * with nothing to re-ingest.
             */
            $table->unsignedSmallInteger('injector_version')->nullable();

            /*
             * §8.15.4's fallback, as applied. Distinct from
             * `projects.chrome_mode`, which is what the project asked for: this
             * is what the build got. A project on `injected` whose artifact
             * could not be injected serves `api_only`, and an operator looking
             * at why needs to see both values rather than infer one.
             */
            $table->enum('chrome_mode_applied', ['injected', 'api_only', 'off'])->nullable();

            // The coverage §8.15.3 asks to be recorded. Two counts rather than
            // a percentage, because a percentage cannot be re-derived into
            // "how many files" and operators ask that second.
            $table->unsignedInteger('chrome_documents')->default(0);
            $table->unsignedInteger('chrome_injected')->default(0);

            /*
             * The samples, and the stubs that are recorded without warning.
             * §8.15.3: navigational stubs "stay in the audit record but must
             * not raise a warning" — so both sets live here and only one of
             * them reaches an operator's notifications.
             */
            $table->json('chrome_coverage')->nullable();
        });

        DataClassification::annotate('builds', [
            ['injector_version', 'operational', 'not_applicable', null, '🛑 §8.15.4; the re-ingest job keys on it'],
            ['chrome_mode_applied', 'operational', 'not_applicable', null, '§8.15.4 fallback as applied, not as asked'],
            ['chrome_documents', 'operational', 'not_applicable', null, '§8.15.3 coverage'],
            ['chrome_injected', 'operational', 'not_applicable', null, '§8.15.3 coverage'],
            [
                'chrome_coverage',
                'operational',
                'not_applicable',
                null,
                '§8.15.3 samples; stubs recorded here without warning',
            ],
        ]);
    }

    public function down(): void
    {
        Schema::table('builds', function (Blueprint $table): void {
            $table->dropColumn([
                'injector_version',
                'chrome_mode_applied',
                'chrome_documents',
                'chrome_injected',
                'chrome_coverage',
            ]);
        });

        DataClassification::forget('builds', [
            'injector_version',
            'chrome_mode_applied',
            'chrome_documents',
            'chrome_injected',
            'chrome_coverage',
        ]);
    }
};
