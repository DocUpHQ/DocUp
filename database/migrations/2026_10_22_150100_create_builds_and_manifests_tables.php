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
 * Builds, their outputs, immutable manifests and the pointer-event log
 * (§8.8, §10.3, §10.4).
 *
 * 🛑 **A version points at a manifest, never at a build** (§8.8.3). The
 * foreign key from `project_versions.published_manifest_id` is added here,
 * because the two tables reference each other and one has to exist first.
 *
 * 🛑 **A note on `version_pointer_events`.** §10.4 names its columns
 * `from_build, to_build`, while §8.8.3 makes the serving pointer a *manifest*.
 * Both are recorded: the manifest ids are what actually flipped, and the build
 * ids are what §10.4 asks for and what a human reading an incident timeline
 * will recognise. In Phase 03's degenerate single-component case there is
 * exactly one build per manifest, so the two agree; once a manifest can span
 * several components they diverge, and the manifest columns are the ones that
 * will still mean something. Recorded here rather than resolved silently — §17
 * says to propose an amendment rather than diverge, and this is the proposal:
 * §10.4's `from_build/to_build` should read `from_manifest/to_manifest`, with
 * the build ids retained as a convenience.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('builds', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_version_id');
            $table->uuidForeign('component_id');

            /*
             * §10.3: UNIQUE. The content key identifies *what was built* — the
             * same inputs produce the same key — so a rebuild of unchanged
             * inputs is recognised rather than repeated. 🛑 §8.7.9 excludes
             * project-scoped input from this key, which is what makes a build
             * shareable between projects mounting the same component.
             */
            $table->char('content_key', 64)->unique();
            $table->binary('plan_digest', 32, true)->nullable();

            $table->char('commit_sha', 40)->nullable();

            /*
             * 🛑 `success_unpublished` is the §8.8.4 outcome that makes the
             * compare-and-swap honest: when the pointer flip affects zero rows
             * another build won the race, and this build terminates here. It is
             * NOT a failure — the artifacts are valid and remain selectable —
             * and conflating it with failure would have operators chasing
             * phantom build errors every time two builds finish together.
             */
            $table->enum('state', [
                'queued',
                'running',
                'published',
                'success_unpublished',
                'failed',
                'cancelled',
            ])->default('queued');

            /*
             * §8.19.15: every failure carries a typed class from a fixed set
             * plus a stable identifier such as `rejected.symlink` or
             * `contract.quota_exceeded`. Stable because operators build alerts
             * and runbooks on these strings; a reworded message is a broken
             * alert.
             */
            $table->enum('failure_class', [
                'rejected', 'config', 'source', 'user', 'contract', 'conflict',
                'timeout', 'resource', 'infra', 'cancelled', 'gate',
            ])->nullable();
            $table->string('failure_identifier', 96)->nullable();
            $table->integer('exit_code')->nullable();

            /*
             * Counted at ingest from the authoritative manifest (§8.8.10), so
             * quota enforcement is exact and free rather than a `du` poll.
             */
            $table->unsignedBigInteger('file_count')->default(0);
            $table->unsignedBigInteger('total_bytes')->default(0);

            $table->datetime('started_at', 3)->nullable();
            $table->datetime('finished_at', 3)->nullable();
            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->index(['project_version_id', 'state']);
            $table->index(['component_id', 'state']);

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_version_id')->references('id')->on('project_versions')->cascadeOnDelete();
            $table->foreign('component_id')->references('id')->on('components')->cascadeOnDelete();
        });

        Schema::create('build_outputs', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('build_id');

            // §10.3's set exactly.
            $table->enum('format', ['html', 'pdf', 'epub', 'htmlzip', 'nav', 'manifest', 'provenance']);

            /*
             * The storage key, relative to the artifact root.
             *
             * 🛑 §8.8.1: keyed **only** by build id — no project slug, version
             * slug, language or user-supplied name appears in it, so renaming a
             * project can never strand or invalidate stored artifacts. An
             * architecture test enforces the shape.
             */
            $table->string('storage_key', 512);

            $table->unsignedBigInteger('file_count')->default(0);
            $table->unsignedBigInteger('total_bytes')->default(0);
            $table->char('content_sha256', 64)->nullable();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique(['build_id', 'format']);

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('build_id')->references('id')->on('builds')->cascadeOnDelete();
        });

        Schema::create('project_version_manifests', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_version_id');

            /*
             * 🛑 **Immutable** (§10.4). Nothing updates a manifest row: a
             * change means a new revision. That is what lets the soft-landing
             * window of §8.8.6 work — the previous manifest is still exactly
             * what the already-delivered HTML expects — and what makes a
             * rollback a pointer flip rather than a rebuild.
             */
            $table->unsignedInteger('revision');

            /*
             * §18.8 lists "a JSON mounts column is fast enough on the hot path"
             * as UNVERIFIED, with the fallback being a normalised
             * `manifest_mounts` child table. Phase 03 does not serve anything
             * (§17: "Nothing is readable over HTTP yet"), so nothing here is on
             * a hot path and the assumption is not yet load-bearing. Phase 04
             * owns the benchmark; if it fails, this column is replaced rather
             * than reinterpreted.
             */
            $table->json('mounts_json');
            $table->json('nav_json')->nullable();
            $table->json('xref_json')->nullable();

            $table->datetime('created_at', 3)->nullable();

            $table->unique(['project_version_id', 'revision']);

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_version_id')->references('id')->on('project_versions')->cascadeOnDelete();
        });

        Schema::create('manifest_builds', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('manifest_id');
            $table->uuidForeign('component_id');
            $table->uuidForeign('build_id');

            $table->datetime('created_at', 3)->nullable();

            // One build per component per manifest: a manifest that named two
            // builds for one component would have no defined resolution.
            $table->unique(['manifest_id', 'component_id']);

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('manifest_id')->references('id')->on('project_version_manifests')->cascadeOnDelete();
            $table->foreign('component_id')->references('id')->on('components')->cascadeOnDelete();
            $table->foreign('build_id')->references('id')->on('builds')->cascadeOnDelete();
        });

        Schema::create('version_pointer_events', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_version_id');

            // What actually flipped (§8.8.3).
            $table->uuidForeign('from_manifest_id', nullable: true);
            $table->uuidForeign('to_manifest_id', nullable: true);

            // §10.4's named columns, retained for legibility. See the class note.
            $table->uuidForeign('from_build_id', nullable: true);
            $table->uuidForeign('to_build_id', nullable: true);

            $table->enum('reason', ['publish', 'rollback', 'gc_repoint']);

            // Null when the system did it (a scheduled repoint).
            $table->uuidForeign('actor_id', nullable: true);

            $table->datetime('created_at', 3)->nullable();

            $table->index(['project_version_id', 'created_at']);

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_version_id')->references('id')->on('project_versions')->cascadeOnDelete();
        });

        // The pointer §8.8.3 insists on, now that manifests exist.
        DB::statement(
            'ALTER TABLE `project_versions`
                ADD CONSTRAINT `project_versions_published_manifest_foreign`
                FOREIGN KEY (`published_manifest_id`)
                REFERENCES `project_version_manifests` (`id`)
                ON DELETE SET NULL'
        );

        DataClassification::annotate('builds', [
            ['id', 'operational', 'not_applicable', 'build_logs', null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['project_version_id', 'operational', 'not_applicable', null, null],
            ['component_id', 'operational', 'not_applicable', null, null],
            ['content_key', 'operational', 'not_applicable', null, '§8.7.9: excludes project-scoped input'],
            ['plan_digest', 'operational', 'not_applicable', null, null],
            ['commit_sha', 'content', 'content', null, 'git provenance; §8.22.9 operator responsibility'],
            ['state', 'operational', 'not_applicable', null, '🛑 success_unpublished is §8.8.4, not a failure'],
            ['failure_class', 'operational', 'not_applicable', null, '§8.19.15 fixed set'],
            ['failure_identifier', 'operational', 'not_applicable', null, '§8.19.15 stable identifier'],
            ['exit_code', 'operational', 'not_applicable', null, null],
            ['file_count', 'operational', 'not_applicable', null, '§8.8.10 quota input, from the manifest'],
            ['total_bytes', 'operational', 'not_applicable', null, '§8.8.10 quota input, from the manifest'],
            ['started_at', 'operational', 'not_applicable', null, null],
            ['finished_at', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('build_outputs', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key'],
            ['build_id', 'operational', 'not_applicable', null, null],
            ['format', 'operational', 'not_applicable', null, '§10.3 set'],
            ['storage_key', 'operational', 'not_applicable', null, '🛑 §8.8.1: build id only, never a slug'],
            ['file_count', 'operational', 'not_applicable', null, null],
            ['total_bytes', 'operational', 'not_applicable', null, null],
            ['content_sha256', 'operational', 'not_applicable', null, 'digest of the manifest describing this output'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('project_version_manifests', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key'],
            ['project_version_id', 'operational', 'not_applicable', null, null],
            ['revision', 'operational', 'not_applicable', null, 'immutable; a change means a new revision'],
            ['mounts_json', 'operational', 'not_applicable', null, '§18.8 unverified on the hot path; P04 benchmarks it'],
            ['nav_json', 'content', 'content', null, 'repository-derived navigation'],
            ['xref_json', 'content', 'content', null, 'repository-derived cross-references'],
            ['created_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('manifest_builds', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key'],
            ['manifest_id', 'operational', 'not_applicable', null, null],
            ['component_id', 'operational', 'not_applicable', null, null],
            ['build_id', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('version_pointer_events', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key'],
            ['project_version_id', 'operational', 'not_applicable', null, null],
            ['from_manifest_id', 'operational', 'not_applicable', null, 'what actually flipped (§8.8.3)'],
            ['to_manifest_id', 'operational', 'not_applicable', null, null],
            ['from_build_id', 'operational', 'not_applicable', null, '§10.4 names these; see the migration note'],
            ['to_build_id', 'operational', 'not_applicable', null, null],
            ['reason', 'operational', 'not_applicable', null, '§10.4: publish, rollback, gc_repoint'],
            ['actor_id', 'pseudonymous', 'platform', null, 'identifies who flipped the pointer'],
            ['created_at', 'operational', 'not_applicable', null, null],
        ]);
    }

    public function down(): void
    {
        DB::statement('ALTER TABLE `project_versions` DROP FOREIGN KEY `project_versions_published_manifest_foreign`');

        Schema::dropIfExists('version_pointer_events');
        Schema::dropIfExists('manifest_builds');
        Schema::dropIfExists('project_version_manifests');
        Schema::dropIfExists('build_outputs');
        Schema::dropIfExists('builds');

        foreach ([
            'version_pointer_events', 'manifest_builds', 'project_version_manifests',
            'build_outputs', 'builds',
        ] as $table) {
            DataClassification::forget($table);
        }
    }
};
