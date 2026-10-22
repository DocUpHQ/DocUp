<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Components and their mounts (§10.2, §10.4).
 *
 * 🛑 Created in **Phase 03**, not Phase 13, and §17 says why: `builds.component_id`
 * and `manifest_builds` have no meaning without them. Phase 03 creates exactly
 * one degenerate component per project with a single primary mount at
 * `mount_path=''`; Phase 13 adds the write-side behaviour that makes components
 * first-class.
 *
 * The point of doing it now rather than later is §8.8.3: documentation is served
 * from an immutable manifest **from the first phase that serves anything**, and a
 * manifest describes mounted components. Introducing the component layer after a
 * serving path existed would be the un-retrofittable change Phase 00 forbids, on
 * the hottest path in the product.
 *
 * `component_sources` is deliberately absent: it carries a foreign key to
 * `repositories`, which arrives with source connection in a later phase. §17
 * lists `components` and `component_mounts` for this phase and not the source
 * table.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('components', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');

            // From `.docup.yaml` `name:` once configuration exists (§8.4).
            // Phase 03 generates it from the project slug for the degenerate case.
            $table->string('key', 100);
            $table->string('name', 190);

            /*
             * 🛑 §8.7.7's ceiling, on the §12.3 lattice. A component may demand
             * MORE protection than the version it is mounted into, and mounting
             * is refused when it does — `stricter(component.min_access,
             * effective visibility)`. Defaulting to `members` rather than
             * `public` means a component created before anyone thinks about
             * access cannot be the thing that publishes it.
             */
            $table->enum('min_access', ['public', 'authenticated', 'members', 'restricted'])
                ->default('members');

            // ADR 0003: relative is the verified default; `injected` is the
            // carve-out for generators that emit root-absolute URLs.
            $table->enum('default_base_url_mode', ['relative', 'injected'])->default('relative');

            // §8.7.14: what happens when two mounts claim the same path.
            // `fail` by default — a silent winner is how one team's page
            // disappears behind another's without anyone being told.
            $table->enum('collision_policy', ['fail', 'priority_wins', 'first_wins'])->default('fail');

            $table->uuidForeign('canonical_project_id', nullable: true);

            // ADVISORY only (§10.2), consumed once at attach. Stored so the
            // suggestion survives, not so anything reads it at serve time.
            $table->string('suggested_mount_path', 255)->nullable();

            $table->enum('state', ['active', 'paused', 'orphaned', 'archived'])->default('active');

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();
            $table->datetime('deleted_at', 3)->nullable()->index();

            $table->unique(['organisation_id', 'key']);
            $table->index('state');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
        });

        Schema::create('component_mounts', function (Blueprint $table): void {
            $table->uuidKey();

            // §8.2.1 tenancy, carried even though it is derivable from the
            // version: a global scope that must join to find the tenant is one
            // the first hand-written query bypasses.
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_version_id');
            $table->uuidForeign('component_id');

            /*
             * '' for the degenerate single-component case (§17, Phase 03).
             *
             * §9.1.5: the unique index is over a hash, not the text. A 255-byte
             * utf8mb4 column is 1020 bytes, and combined with the version key in
             * one index that approaches InnoDB's limit; the hash is fixed-width
             * and exact.
             */
            $table->string('mount_path', 255)->default('');
            $table->binary('mount_path_hash', 20, true)->storedAs('UNHEX(SHA1(mount_path))');

            // Which build of the component this mount resolves to. §8.8.7 makes
            // a release-kind version rewrite every mount to `pinned_build` at
            // promotion, so a shipped release can never drift.
            $table->enum('selector_kind', ['latest_success', 'ref', 'pinned_build'])->default('latest_success');
            $table->string('selector_value', 255)->nullable();

            $table->boolean('is_required')->default(true);
            $table->boolean('is_primary')->default(false);

            /*
             * 🛑 The §18.21 idiom, verified on MySQL 8.4.11 before this
             * migration was written (§18.21, P03): a UNIQUE index over a STORED
             * generated column yielding NULL permits unlimited NULLs and
             * rejects the second non-NULL.
             *
             * So "at most one primary mount per version" is enforced by the
             * database rather than by application code with a race window. The
             * verification mattered: the fallback §18.21 names is "enforce in
             * the application with a documented race window and a
             * reconciliation job — strictly worse".
             */
            $table->tinyInteger('primary_marker')->nullable()->storedAs('IF(is_primary=1,1,NULL)');

            // §8.7.7: snapshotted at mount time and re-checked AFTER mount
            // match (§12.3), so a later widening of the component cannot
            // retroactively expose what was mounted under the old ceiling.
            $table->enum('min_access_snapshot', ['public', 'authenticated', 'members', 'restricted'])
                ->default('members');

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique(['project_version_id', 'mount_path_hash'], 'component_mounts_path_unique');
            $table->unique(['project_version_id', 'component_id'], 'component_mounts_component_unique');
            $table->unique(['project_version_id', 'primary_marker'], 'component_mounts_primary_unique');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('component_id')->references('id')->on('components')->cascadeOnDelete();
            $table->foreign('project_version_id')->references('id')->on('project_versions')->cascadeOnDelete();
        });

        DataClassification::annotate('components', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['key', 'operational', 'not_applicable', null, 'from .docup.yaml name:'],
            ['name', 'operational', 'not_applicable', null, null],
            ['min_access', 'operational', 'not_applicable', null, '§8.7.7 ceiling on the §12.3 lattice'],
            ['default_base_url_mode', 'operational', 'not_applicable', null, 'ADR 0003'],
            ['collision_policy', 'operational', 'not_applicable', null, '§8.7.14'],
            ['canonical_project_id', 'operational', 'not_applicable', null, 'cross-reference fallback target'],
            ['suggested_mount_path', 'operational', 'not_applicable', null, 'advisory; consumed once at attach'],
            ['state', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
            ['deleted_at', 'operational', 'not_applicable', null, '§8.22.6 recovery window'],
        ]);

        DataClassification::annotate('component_mounts', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['project_version_id', 'operational', 'not_applicable', null, null],
            ['component_id', 'operational', 'not_applicable', null, null],
            ['mount_path', 'operational', 'not_applicable', null, "'' for the degenerate single-component case"],
            ['mount_path_hash', 'derived', 'not_applicable', null, '§9.1.5 companion hash for the unique index'],
            ['selector_kind', 'operational', 'not_applicable', null, '§8.8.7'],
            ['selector_value', 'operational', 'not_applicable', null, null],
            ['is_required', 'operational', 'not_applicable', null, null],
            ['is_primary', 'operational', 'not_applicable', null, null],
            ['primary_marker', 'derived', 'not_applicable', null, '🛑 §18.21 idiom: one primary per version, enforced by the database'],
            ['min_access_snapshot', 'operational', 'not_applicable', null, '§8.7.7 re-checked after mount match'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('component_mounts');
        Schema::dropIfExists('components');

        foreach (['component_mounts', 'components'] as $table) {
            DataClassification::forget($table);
        }
    }
};
