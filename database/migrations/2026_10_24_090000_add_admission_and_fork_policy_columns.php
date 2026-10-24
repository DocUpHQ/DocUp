<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * §8.5.5's "deficit round-robin **weighted by organisation share**".
 *
 * 🛑 One column, and it is here rather than in configuration because the
 * weight is per organisation and configuration is per installation. A
 * `DOCUP_ADMISSION_WEIGHTS` environment variable holding a map of
 * organisation ids would be a database table written in the wrong place,
 * and it would be edited by hand on a running system.
 *
 * The default of 1 is what makes `fair` fair out of the box: every
 * organisation earns one grant per rotation, so the first queued build of
 * an idle organisation is reached after at most one grant to each
 * organisation ahead of it — never after the whole of somebody's backlog,
 * which is the Read the Docs behaviour §8.5.5 names as a bug.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('organisations', function (Blueprint $table): void {
            /*
             * Small, unsigned and defaulted. A share of zero would earn no
             * grants at all, so the dispatcher floors it at 1 rather than
             * letting a stray update silently suspend an organisation's
             * builds — suspension is an operator action with an audit
             * trail, not a side effect of a number.
             */
            $table->unsignedSmallInteger('build_share')->default(1)->after('id');
        });

        DataClassification::annotate('organisations', [
            ['build_share', 'operational', 'not_applicable', null, '§8.5.5 deficit round-robin weight'],
        ]);

        /*
         * 🛑 §8.5.10: "Fork and pull-request builds MUST receive **no
         * secrets at all** and MUST have egress force-downgraded to the
         * allowlist. Fork-PR builds MUST be **off by default** with an
         * explicit opt-in and a written threat statement."
         *
         * Two columns, because the requirement has two halves that belong
         * at different scopes: whether a *request* came from a fork is a
         * property of the delivery, and whether this installation will
         * build one at all is a property of the *project* whose maintainers
         * accept the risk. One column could not express "this push is from
         * a fork" and "this project permits that" at the same time.
         *
         * Nothing sets `from_fork` yet — the provider webhooks that would
         * are §8.5.4's and arrive in Phase 11, and previews are Phase 32.
         * The column exists now because the refusal does: a flag added
         * later, alongside the first code that honours it, is a flag whose
         * default nobody argued about.
         */
        Schema::table('build_requests', function (Blueprint $table): void {
            $table->boolean('from_fork')->default(false)->after('payload_truncated');
        });

        Schema::table('projects', function (Blueprint $table): void {
            $table->boolean('fork_builds_enabled')->default(false)->after('visibility');
        });

        DataClassification::annotate('build_requests', [
            ['from_fork', 'operational', 'not_applicable', null, '🛑 §8.5.10: a fork build receives no secrets'],
        ]);

        DataClassification::annotate('projects', [
            ['fork_builds_enabled', 'operational', 'not_applicable', null, '🛑 §8.5.10: off by default; explicit opt-in'],
        ]);
    }

    public function down(): void
    {
        DataClassification::forget('organisations', ['build_share']);
        DataClassification::forget('build_requests', ['from_fork']);
        DataClassification::forget('projects', ['fork_builds_enabled']);

        Schema::table('organisations', function (Blueprint $table): void {
            $table->dropColumn('build_share');
        });

        Schema::table('build_requests', function (Blueprint $table): void {
            $table->dropColumn('from_fork');
        });

        Schema::table('projects', function (Blueprint $table): void {
            $table->dropColumn('fork_builds_enabled');
        });
    }
};
