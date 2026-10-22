<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Project versions (§8.6, §10.4, §8.8.3–§8.8.7).
 *
 * 🛑 This table holds the **pointer that serving reads**, and §8.8.3 is
 * emphatic about its shape: documentation is served from an immutable manifest
 * row referenced by `published_manifest_id`, never from a build id. "A later
 * move from `current_build_id` to a manifest pointer would be exactly the
 * un-retrofittable change Phase 00 forbids, on the hottest path in the
 * product." So the pointer is a manifest from the first migration that creates
 * it, even though Phase 03's manifests all describe a single degenerate
 * component.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('project_versions', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_id');

            $table->string('slug', 80);

            /*
             * §8.8.7: `publish_mode` defaults to `auto` for channel-kind and
             * `manual` for release-kind, so the default depends on this column
             * and is applied by the application at creation.
             */
            $table->enum('kind', ['channel', 'release'])->default('channel');

            /*
             * 🛑 §8.6.12 makes language a property of the VERSION, which is why
             * §10.4 insists the unique key is (project_id, language, slug) and
             * **not** (project_id, slug): `/en/v2/` and `/ja/v2/` are two rows
             * sharing a slug by design. Getting this wrong would make a
             * translated version impossible to express without renaming it.
             */
            $table->char('language', 5)->default('en');
            $table->uuidForeign('translation_group_id', nullable: true);

            $table->boolean('active')->default(true);
            $table->boolean('listed')->default(true);
            $table->boolean('published')->default(false);

            // The §12.3 lattice again. §12.3 evaluates project visibility first
            // and this second; both are stored and both authoritative.
            $table->enum('visibility', ['public', 'authenticated', 'members', 'restricted'])
                ->default('restricted');

            $table->enum('publish_mode', ['auto', 'manual'])->default('auto');

            /*
             * 🛑 §8.8.3: the serving pointer is a MANIFEST, not a build.
             *
             * Nullable because a version exists before anything is published to
             * it. The foreign key is added by the manifests migration, since
             * the two tables reference each other and one has to be created
             * first.
             */
            $table->uuidForeign('published_manifest_id', nullable: true);

            /*
             * §8.8.5–§8.8.6. The previous manifest stays resolvable for a
             * bounded soft-landing window after a flip, so a page loaded
             * moments before can still fetch its relative assets. Without it,
             * every publish breaks every page currently open — the assets move
             * under a new build prefix and the already-delivered HTML still
             * points at the old one.
             */
            $table->uuidForeign('previous_manifest_id', nullable: true);
            $table->datetime('soft_landing_until', 3)->nullable();

            /*
             * §8.8.5: rollback is the pointer flip backwards **plus a pin that
             * blocks automatic republication until a human unpins**. Without
             * the pin, the next successful build immediately republishes the
             * thing that was just rolled back — which is the worst possible
             * response to someone deciding a release was bad.
             */
            $table->boolean('pinned')->default(false);
            $table->string('pinned_reason', 255)->nullable();
            $table->datetime('pinned_at', 3)->nullable();
            $table->uuidForeign('pinned_by', nullable: true);

            // Bumped on every flip, for the §10.8 invalidation registry.
            $table->unsignedBigInteger('serving_epoch')->default(1);

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();
            $table->datetime('deleted_at', 3)->nullable()->index();

            $table->unique(['project_id', 'language', 'slug'], 'project_versions_slug_unique');
            $table->index(['project_id', 'active', 'published']);

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_id')->references('id')->on('projects')->cascadeOnDelete();
        });

        DataClassification::annotate('project_versions', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['project_id', 'operational', 'not_applicable', null, null],
            ['slug', 'operational', 'not_applicable', null, 'appears in published URLs; never reused (§8.2.8)'],
            ['kind', 'operational', 'not_applicable', null, 'drives the §8.8.7 publish_mode default'],
            ['language', 'operational', 'not_applicable', null, '🛑 §8.6.12: part of the unique key, not a label'],
            ['translation_group_id', 'operational', 'not_applicable', null, null],
            ['active', 'operational', 'not_applicable', null, null],
            ['listed', 'operational', 'not_applicable', null, null],
            ['published', 'operational', 'not_applicable', null, null],
            ['visibility', 'operational', 'not_applicable', null, '§12.3 lattice; authoritative at decision time'],
            ['publish_mode', 'operational', 'not_applicable', null, '§8.8.7'],
            ['published_manifest_id', 'operational', 'not_applicable', null, '🛑 §8.8.3: a manifest, never a build id'],
            ['previous_manifest_id', 'operational', 'not_applicable', null, '§8.8.6 soft-landing window'],
            ['soft_landing_until', 'operational', 'not_applicable', null, '§8.8.6, default 5 minutes'],
            ['pinned', 'operational', 'not_applicable', null, '§8.8.5: blocks automatic republication after rollback'],
            ['pinned_reason', 'operational', 'not_applicable', null, null],
            ['pinned_at', 'operational', 'not_applicable', null, null],
            ['pinned_by', 'pseudonymous', 'platform', null, 'identifies the person who pinned'],
            ['serving_epoch', 'operational', 'not_applicable', null, '§10.8 invalidation registry'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
            ['deleted_at', 'operational', 'not_applicable', null, '§8.22.6 recovery window'],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('project_versions');

        DataClassification::forget('project_versions');
    }
};
