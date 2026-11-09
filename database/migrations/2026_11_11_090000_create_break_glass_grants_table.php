<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * 🛑 §8.12.20's break-glass read override.
 *
 * > "An installation-owner **break-glass** read override MUST exist behind MFA,
 * > step-up re-authentication and a mandatory reason, rate-limited to 3/hour,
 * > raising an operator alert and audited."
 *
 * ## 🛑 Why this is a table and not a session flag
 *
 * A session flag would be invisible: nobody could answer "who read what, and
 * why" after the fact, and §8.12.20's audit and alert requirements both presume
 * the answer exists. A row per activation makes the override a **record** — the
 * reason is stored beside the project it was used on and the window it was open
 * for, and the audit chain references the row rather than restating it.
 *
 * 🛑 And the rate limit is counted from this table rather than from a cache
 * bucket, which is the second reason it is a table. A Valkey counter resets on
 * a flush, an eviction or a restart, so "3 per hour" would be an honest claim
 * only while the cache happened to be healthy. Counting rows cannot be reset
 * without leaving a trace in a table whose rows are audited.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('break_glass_grants', function (Blueprint $table): void {
            $table->uuidKey();

            /*
             * The project's organisation, for §8.2.1 tenancy on the dashboard
             * side. 🛑 The serving path reads this table with a raw query and no
             * tenant context, exactly as it reads `docs_sessions`, because
             * §8.9.4 gives documentation requests no tenant to declare.
             */
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_id');

            /*
             * 🛑 The installation owner who opened it. Break-glass is a
             * **person's** act, not a role's: §8.12.20 says
             * "installation-owner", and the audit question is always "who".
             */
            $table->uuidForeign('user_id');

            /*
             * 🛑 §8.12.20's "mandatory reason", stored rather than only logged.
             *
             * `varchar(500)` rather than `text`: a bound is what makes the field
             * answerable in a review, and an operator pasting a stack trace into
             * it is a reason nobody will read. The minimum is enforced in
             * `App\Access\BreakGlass`, because "mandatory" has to mean more
             * than "not empty" — a single character satisfies NOT NULL.
             */
            $table->string('reason', 500);

            $table->datetime('opened_at', 3);

            /*
             * 🛑 Indexed because the serving path asks "is there an open grant
             * for this user and project **now**" on every request a dashboard
             * member makes to the documentation origin.
             */
            $table->datetime('expires_at', 3);

            /*
             * Closed early, by the owner or by an administrator. Distinct from
             * expiry: a grant that was closed deliberately is evidence of
             * discipline, and one that ran its full window is not.
             */
            $table->datetime('closed_at', 3)->nullable();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            /*
             * 🛑 The serving path's one lookup, in the order it asks: this user,
             * this project, still open. Covering, so the per-request cost of
             * having the feature at all is one index seek for the small
             * population of dashboard members browsing documentation — and
             * nothing for everybody else, because the resolver does not query
             * unless the session carries a `user_id`.
             */
            $table->index(['user_id', 'project_id', 'expires_at'], 'break_glass_active_index');

            /* §8.12.20's rate limit: three per hour, per person. */
            $table->index(['user_id', 'opened_at'], 'break_glass_rate_index');

            $table->index(['organisation_id', 'opened_at'], 'break_glass_tenant_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_id')->references('id')->on('projects')->cascadeOnDelete();
            $table->foreign('user_id')->references('id')->on('users')->cascadeOnDelete();
        });

        DataClassification::annotate('break_glass_grants', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['project_id', 'operational', 'not_applicable', null, null],
            /*
             * 🛑 The `note` column is `varchar(255)`, so the argument for
             * these two classifications is here in the migration and the note is
             * the summary of it.
             *
             * Both cascade with the account (`platform` erasure, via the
             * `user_id` foreign key), which means the record of an override does
             * NOT survive the person who opened it in this table. That is
             * correct and it is also why §8.12.20 requires the activation
             * **audited**: §8.22.5's chain is append-only, carries the actor
             * and the reason in its own payload, and is the reviewable copy.
             * Pointing a review at a row that can be erased would be the
             * requirement satisfied in form only.
             */
            ['user_id', 'personal', 'platform', 'audit_events', 'cascades with the account; the audit chain is the reviewable copy (§8.22.5)'],
            ['reason', 'personal', 'platform', 'audit_events', 'operator prose, may name a person; chain holds the reviewable copy'],
            ['opened_at', 'operational', 'not_applicable', 'audit_events', null],
            ['expires_at', 'operational', 'not_applicable', 'audit_events', '§8.12.20: the window, not a TTL'],
            ['closed_at', 'operational', 'not_applicable', 'audit_events', 'closed early is evidence; expired is not'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);
    }

    public function down(): void
    {
        DataClassification::forget('break_glass_grants');

        Schema::dropIfExists('break_glass_grants');
    }
};
