<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Organisations and teams (§8.2.1, §8.2.3, §10.1).
 *
 * 🛑 The organisation is the tenancy boundary. §8.2.1 requires every
 * tenant-reachable row to carry `organisation_id` under a global query scope —
 * including rows where it is derivable, as `team_members.organisation_id` is
 * derivable from its team. The redundancy is the point: a global scope that has
 * to join to find the tenant is a global scope that gets bypassed by the first
 * query someone writes by hand, and cross-tenant leakage is §14's top finding.
 *
 * §8.22.13: timestamps are UTC `DATETIME(3)`, never `TIMESTAMP`. Laravel's
 * `timestamps()` emits `TIMESTAMP` by default, so every table here declares
 * `datetime(..., 3)` explicitly.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('organisations', function (Blueprint $table): void {
            $table->uuidKey();

            $table->string('name', 160);

            // Globally unique: organisations are the tenancy root, so a slug
            // identifies one without further context.
            //
            // Unlike project slugs (§8.2.8) an organisation slug IS reusable
            // once the row is hard-purged. §8.2.8 reserves project and version
            // slugs specifically, and reserving more than the specification
            // asks for would mean a tombstone table nothing reads.
            $table->string('slug', 80)->unique();

            // §8.22.13: users have a display timezone with an organisation
            // default, so the default lives here.
            $table->string('default_timezone', 64)->default('UTC');

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            // 🛑 §8.22.6: a recovery window, not a state. The mandatory 30-day
            // hard purge is scheduled work, not an operator option, and it is
            // the documented erasure latency floor. A soft-deleted row left
            // indefinitely retains personal data while the product claims
            // erasure.
            $table->datetime('deleted_at', 3)->nullable()->index();
        });

        Schema::create('teams', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');

            $table->string('name', 160);
            $table->string('slug', 80);

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();
            $table->datetime('deleted_at', 3)->nullable()->index();

            $table->unique(['organisation_id', 'slug']);

            $table->foreign('organisation_id')
                ->references('id')->on('organisations')
                ->cascadeOnDelete();
        });

        /*
         * §12.1 is explicit that team membership and permission resolution are
         * different things: the starter kit's Teams scaffolding is used for
         * membership only, and roles resolve through `role_assignments`. A team
         * is a convenient way to name a set of people, not an authorisation
         * primitive — which is why there is no `role` column here.
         */
        Schema::create('team_members', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('team_id');
            $table->uuidForeign('user_id');

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique(['team_id', 'user_id']);

            $table->foreign('organisation_id')
                ->references('id')->on('organisations')
                ->cascadeOnDelete();
            $table->foreign('team_id')
                ->references('id')->on('teams')
                ->cascadeOnDelete();
            $table->foreign('user_id')
                ->references('id')->on('users')
                ->cascadeOnDelete();
        });

        DataClassification::annotate('organisations', [
            ['id', 'operational', 'not_applicable', null, 'tenancy identifier; not about a person'],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['name', 'operational', 'not_applicable', null, 'may be a sole trader name, but is published by choice'],
            ['slug', 'operational', 'not_applicable', null, 'appears in URLs'],
            ['default_timezone', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
            ['deleted_at', 'operational', 'not_applicable', null, '§8.22.6 recovery window; hard purge at 30 days'],
        ]);

        DataClassification::annotate('teams', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['name', 'operational', 'not_applicable', null, 'team names occasionally carry a person\'s name'],
            ['slug', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
            ['deleted_at', 'operational', 'not_applicable', null, '§8.22.6 recovery window'],
        ]);

        DataClassification::annotate('team_members', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['team_id', 'operational', 'not_applicable', null, null],
            // The association is the personal datum here: "this person belongs
            // to that team" is about a person even though neither identifier is
            // readable on its own.
            ['user_id', 'pseudonymous', 'platform', null, 'links a person to a team; erased with the user'],
            ['created_at', 'operational', 'platform', null, 'reveals when a person joined'],
            ['updated_at', 'operational', 'platform', null, null],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('team_members');
        Schema::dropIfExists('teams');
        Schema::dropIfExists('organisations');

        DataClassification::forget('team_members');
        DataClassification::forget('teams');
        DataClassification::forget('organisations');
    }
};
