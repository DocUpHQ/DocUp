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
 * §8.7.8's explicit grants, and the one change that makes §8.7.9's "build
 * once" true rather than aspirational.
 *
 * Phase 03 created `components` and `component_mounts` with all three of
 * §8.7.3's unique constraints; Phase 05 created `component_sources`. What was
 * missing was the grant table, and a `builds` row that can serve more than
 * one project.
 */
return new class extends Migration
{
    public function up(): void
    {
        /*
         * 🛑 §8.7.8: "Mounting a component a team does not own MUST require
         * an explicit `component_grants` row. Mounting is not implicitly
         * organisation-wide."
         *
         * The requirement's own reason is §8.7.7's: a product whose headline
         * feature is per-project authentication cannot let any project admin
         * mount any component. The ceiling stops a *declassification*; the
         * grant stops the mount happening at all.
         *
         * Grantee is a TEAM, not a user: §8.2 models permission through
         * teams, and a grant to a person is a grant that leaves with them.
         */
        Schema::create('component_grants', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('component_id', index: false);
            $table->uuidForeign('team_id', index: false);

            /*
             * What the grant permits. `mount` is the only verb today and the
             * column is an enum rather than a boolean because §8.7.7's
             * "Loosening a ceiling MUST be a separate audited action" will
             * want `manage` beside it, and widening an enum is a migration
             * while reinterpreting a boolean is a guess.
             */
            $table->enum('capability', ['mount'])->default('mount');

            $table->uuidForeign('granted_by', nullable: true);
            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            /*
             * One grant per (component, team, capability). A second row
             * would be a second answer to a yes/no question.
             */
            $table->unique(['component_id', 'team_id', 'capability'], 'component_grants_unique');
            $table->index(['organisation_id', 'team_id']);

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('component_id')->references('id')->on('components')->cascadeOnDelete();
            $table->foreign('team_id')->references('id')->on('teams')->cascadeOnDelete();
        });

        /*
         * 🛑 The owning team, on the component itself.
         *
         * §8.7.8 says a grant is needed to mount a component "a team does not
         * own", which presupposes ownership. Without this column every
         * component is owned by nobody and either every mount needs a grant
         * (unusable) or none does (the requirement is decorative).
         *
         * Nullable, because §8.7.1 makes a component organisation-scoped and
         * an installation with no teams yet still has components. Null means
         * "owned by the organisation", which every project admin may mount —
         * stated here because the alternative reading, "owned by nobody, so
         * nobody may mount it", would make existing components unmountable
         * the moment this migration ran.
         */
        // No `->after()`: `uuidForeign` is a Blueprint macro and returns
        // void, and column order in MySQL is cosmetic anyway.
        Schema::table('components', function (Blueprint $table): void {
            $table->uuidForeign('owner_team_id', nullable: true, index: false);
        });

        Schema::table('components', function (Blueprint $table): void {
            $table->foreign('owner_team_id')->references('id')->on('teams')->nullOnDelete();
        });

        /*
         * 🛑 §8.7.9, and the reason this phase exists: "Builds MUST be
         * identified by a content key over `organisation_id`,
         * `component_id`, `commit_sha`, config digest, builder image,
         * builder version, and — only when `base_url_mode='injected'` — the
         * mount path; enforced `UNIQUE`, and satisfied from an existing
         * successful build with the same key. This is what makes one
         * repository feeding many projects build **once**."
         *
         * A build identified by that key belongs to a COMPONENT. It cannot
         * also belong to a project version, and `project_version_id` was
         * `NOT NULL ... cascadeOnDelete` — so deleting one project's version
         * would have deleted the build row two other projects were serving
         * from. That is not a tidiness problem; it is a reader seeing a 404
         * because somebody else tidied up.
         *
         * §10.3's own column list for `builds` has no `project_version_id`,
         * which is the same statement from the other direction.
         *
         * The column stays, nullable, meaning **the project version whose
         * request first caused this build** — which is what `BuildProgress`'s
         * queue estimate and §8.5.2's short-circuit read it for, and both
         * are honest about a build being reused: a second project's first
         * build of a shared component is genuinely not in its own history.
         * Which versions a build SERVES is the published manifest's answer
         * and nothing else's.
         */
        Schema::table('builds', function (Blueprint $table): void {
            $table->dropForeign(['project_version_id']);
        });

        DB::statement('ALTER TABLE `builds` MODIFY `project_version_id` BINARY(16) NULL');

        Schema::table('builds', function (Blueprint $table): void {
            $table->foreign('project_version_id')->references('id')->on('project_versions')->nullOnDelete();
        });

        /*
         * 🛑 §8.7.11's `base_url_mode`, per MOUNT rather than per component.
         *
         * `components.default_base_url_mode` has existed since Phase 03 and
         * is what its name says: a default. The mode that decides a build's
         * content key is the one the MOUNT uses, because §8.7.9 puts "the
         * mount path" in the key "only when `base_url_mode='injected'`" —
         * and the mount path is the mount's.
         *
         * Nullable, meaning "take the component's default". Two columns
         * rather than copying the default in, so that changing a component's
         * default reaches every mount that did not override it.
         */
        Schema::table('component_mounts', function (Blueprint $table): void {
            $table->enum('base_url_mode', ['relative', 'injected'])
                ->nullable()
                ->after('mount_path_hash');
        });

        DataClassification::annotate('component_grants', [
            ['id', 'pseudonymous', 'platform', null, 'surrogate key'],
            ['organisation_id', 'pseudonymous', 'platform', 'organisations', 'tenancy'],
            ['component_id', 'pseudonymous', 'platform', 'components', '🛑 §8.7.8: what may be mounted'],
            ['team_id', 'pseudonymous', 'platform', 'teams', '🛑 §8.7.8: by whom'],
            ['capability', 'operational', 'not_applicable', null, 'mount today; manage when §8.7.7 loosening ships'],
            ['granted_by', 'pseudonymous', 'platform', 'users', 'who decided'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('components', [
            ['owner_team_id', 'pseudonymous', 'platform', 'teams', '🛑 §8.7.8: null means organisation-owned'],
        ]);

        DataClassification::annotate('component_mounts', [
            ['base_url_mode', 'operational', 'not_applicable', null, '§8.7.11: injected puts the mount path in the content key'],
        ]);
    }

    public function down(): void
    {
        DataClassification::forget('component_mounts', ['base_url_mode']);

        Schema::table('component_mounts', function (Blueprint $table): void {
            $table->dropColumn('base_url_mode');
        });

        Schema::table('builds', function (Blueprint $table): void {
            $table->dropForeign(['project_version_id']);
        });

        /*
         * A build whose triggering version has since been deleted has a null
         * here, and the column is about to be NOT NULL again. Those rows
         * cannot be reconstructed — the version is gone — so the rollback
         * removes them rather than inventing a parent. Said out loud because
         * a rollback that destroys rows should never be a surprise.
         */
        DB::table('builds')->whereNull('project_version_id')->delete();

        DB::statement('ALTER TABLE `builds` MODIFY `project_version_id` BINARY(16) NOT NULL');

        Schema::table('builds', function (Blueprint $table): void {
            $table->foreign('project_version_id')->references('id')->on('project_versions')->cascadeOnDelete();
        });

        DataClassification::forget('components', ['owner_team_id']);

        Schema::table('components', function (Blueprint $table): void {
            $table->dropForeign(['owner_team_id']);
            $table->dropColumn('owner_team_id');
        });

        DataClassification::forget('component_grants');
        Schema::dropIfExists('component_grants');
    }
};
