<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * §8.5.21–§8.5.23 and §8.5.17: a build you can watch, cancel and trust.
 *
 * 🛑 **There is no `build_log_lines` table, and that is §10.3's decision
 * rather than an omission.** The storage layout names
 * `logs/<project_uuid>/<build_uuid>/log.ndjson.gz` — a file, not rows. A
 * 10 MiB log is roughly 80,000 rows, written one at a time while a build
 * runs, read back in order and then deleted at 90 days; an append-only file
 * does all of that with one `fwrite` per line and no index to maintain.
 * What the database keeps is the *metadata* an API needs to answer without
 * opening the file: how many lines there are, how large it is, and whether
 * it was capped.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('builds', function (Blueprint $table): void {
            /*
             * §8.5.22's offset contract answers "is there more?" from these
             * rather than by stat-ing a file on every poll. A browser polling
             * a nine-minute build asks perhaps 200 times; each answer should
             * cost one row read.
             */
            $table->unsignedInteger('log_lines')->default(0)->after('exit_code');
            $table->unsignedBigInteger('log_bytes')->default(0)->after('log_lines');

            /*
             * 🛑 §8.5.21's cap, as a fact about this build rather than an
             * inference from the size. A log that happens to be 10 MiB and a
             * log that was *cut* to 10 MiB are different things to an author
             * reading the top of it, and only the second has lines missing
             * from the middle.
             */
            $table->boolean('log_capped')->default(false)->after('log_bytes');

            /*
             * §8.5.23: "support cancelling a running build with effect within
             * 5 seconds". The request is a column rather than a queue message
             * because the thing that must see it is the runner, which has no
             * database — the worker reads this and writes a marker into the
             * spool, so the request survives a worker restart in between.
             */
            $table->datetime('cancel_requested_at', 3)->nullable()->after('log_capped');
            $table->uuidForeign('cancel_requested_by', nullable: true, index: false);
        });

        Schema::table('projects', function (Blueprint $table): void {
            /*
             * 🛑 §8.5.22: "build-log visibility for anonymous readers of
             * public projects MUST be a per-project setting defaulting to
             * **off** (build logs leak paths, dependency versions and
             * sometimes content)."
             *
             * Named for what it controls rather than as a boolean called
             * `public`: the setting is about one audience — anonymous readers
             * — and never about members, who read logs under the project's
             * own policy either way.
             */
            $table->boolean('anonymous_build_logs')->default(false)->after('visibility');

            /*
             * §8.5.17's governor. The count is of CONSECUTIVE failures of the
             * project's default version in user-caused classes; anything else
             * resets it, and 🛑 infrastructure failures neither increment nor
             * reset it, because "Infrastructure failures MUST NEVER disable a
             * tenant" and a reset would be just as wrong — it would let our
             * own outage launder somebody's broken configuration.
             */
            $table->unsignedInteger('consecutive_build_failures')->default(0)->after('anonymous_build_logs');

            /*
             * When webhook triggering was disabled, and nothing else. §8.5.17
             * is explicit that manual building stays available, so this is
             * deliberately not a `builds_disabled_at`: the name is the scope.
             */
            $table->datetime('webhook_triggering_disabled_at', 3)->nullable()->after('consecutive_build_failures');
        });

        DataClassification::annotate('builds', [
            ['log_lines', 'operational', 'not_applicable', null, '§8.5.22 offset contract'],
            ['log_bytes', 'operational', 'not_applicable', null, '§8.5.21'],
            ['log_capped', 'operational', 'not_applicable', null, '§8.5.21 head 2 MiB + tail 8 MiB'],
            ['cancel_requested_at', 'operational', 'not_applicable', null, '§8.5.23'],
            ['cancel_requested_by', 'pseudonymous', 'platform', 'builds', 'the actor who cancelled the build'],
        ]);

        DataClassification::annotate('projects', [
            ['anonymous_build_logs', 'operational', 'not_applicable', null, '🛑 §8.5.22: defaults to off'],
            ['consecutive_build_failures', 'operational', 'not_applicable', null, '§8.5.17 governor counter'],
            ['webhook_triggering_disabled_at', 'operational', 'not_applicable', null, '🛑 §8.5.17: webhooks only, never manual'],
        ]);
    }

    public function down(): void
    {
        DataClassification::forget('builds', [
            'log_lines', 'log_bytes', 'log_capped', 'cancel_requested_at', 'cancel_requested_by',
        ]);

        DataClassification::forget('projects', [
            'anonymous_build_logs', 'consecutive_build_failures', 'webhook_triggering_disabled_at',
        ]);

        Schema::table('builds', function (Blueprint $table): void {
            $table->dropColumn([
                'log_lines', 'log_bytes', 'log_capped', 'cancel_requested_at', 'cancel_requested_by',
            ]);
        });

        Schema::table('projects', function (Blueprint $table): void {
            $table->dropColumn([
                'anonymous_build_logs', 'consecutive_build_failures', 'webhook_triggering_disabled_at',
            ]);
        });
    }
};
