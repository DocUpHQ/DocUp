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
 * Phase 14's tables: the record of what a composition resolved to (§10.4).
 *
 * Phase 13 made one repository feed many projects. This is the other
 * direction — many repositories into one project — and the difference in
 * the schema is that a mount can no longer be assumed to resolve to the
 * build that has just finished. It resolves through a **selector** (§8.7.5),
 * which means the resolution is a decision, and §8.8.8 requires every
 * decision of that kind to be written down:
 *
 * > "Every selector resolution MUST be recorded as an append-only row, and
 * > every unpublished composition change as a drift event carrying the
 * > per-mount before/after ref, commit and build id."
 *
 * Hence `mount_resolutions` and `project_version_drift_events`. The third
 * table, `manifest_link_issues`, is §8.7.16's: a cross-component reference
 * that does not resolve is recorded rather than fatal, because "one
 * repository's typo must not break another repository's build".
 */
return new class extends Migration
{
    public function up(): void
    {
        /*
         * 🛑 §8.7.5's seven selectors, replacing Phase 03's three.
         *
         * `latest_success` survives as the eighth because it is the default
         * for the degenerate single-component case every project starts in,
         * and because it is the only selector that means "whatever built
         * last" — which is what a project with one repository and no release
         * process actually wants. §8.7.5 names the seven a project composing
         * several repositories needs; it does not say the trivial case must
         * pick one of them.
         *
         * `ref` becomes `pinned_ref`, which is the same thing under §8.7.5's
         * name. Rewritten in place rather than kept as a synonym: two spellings
         * of one selector is how a resolver grows a branch nobody tests.
         */
        DB::statement(
            'ALTER TABLE component_mounts MODIFY selector_kind ENUM('
            ."'latest_success','ref','pinned_build','pinned_ref','track_branch',"
            ."'track_tag_pattern','track_semver_range','latest_release','mirror_label'"
            .") NOT NULL DEFAULT 'latest_success'"
        );

        DB::table('component_mounts')->where('selector_kind', 'ref')->update(['selector_kind' => 'pinned_ref']);

        DB::statement(
            'ALTER TABLE component_mounts MODIFY selector_kind ENUM('
            ."'latest_success','pinned_build','pinned_ref','track_branch',"
            ."'track_tag_pattern','track_semver_range','latest_release','mirror_label'"
            .") NOT NULL DEFAULT 'latest_success'"
        );

        Schema::table('component_mounts', function (Blueprint $table): void {
            /*
             * 🛑 §8.7.5: "`mirror_label` MUST support fallback modes
             * `newest_semver_lte`, `newest` and `fail`".
             *
             * Nullable because it is meaningless for the other seven, and a
             * default would make a column that reads as configured when
             * nobody configured it. The resolver refuses a `mirror_label`
             * mount with no fallback rather than picking one, because the
             * three answers differ in exactly the way a shipped release
             * cares about: `fail` keeps a stale composition off the site,
             * `newest` prefers currency over correctness, and
             * `newest_semver_lte` is the one §8.7.5 exists for.
             */
            $table->enum('mirror_fallback', ['newest_semver_lte', 'newest', 'fail'])
                ->nullable()
                ->after('selector_value');

            /*
             * §8.7.15's "explicit audited override". A mount path that is a
             * prefix of, or prefixed by, an existing one is refused by
             * default; this column is the operator saying they meant it, and
             * the publish then generates a redirect row for every shadowed
             * path found in the affected builds' file manifests.
             *
             * Per mount rather than per project, and so **not** in §20.4's
             * unsafe-modes registry — §20.4's own carve-out names "the
             * §8.7.15 shadowing override" among the weakenings that are per
             * project or per component. It is still audited on change.
             */
            $table->boolean('shadowing_override')->default(false)->after('is_primary');
        });

        /*
         * §8.7.6's layout tree, on the version rather than on the project.
         *
         * > "Each project version holds a **layout tree** whose nodes are
         * > labels, literal links or `{"include": "<component key>"}`
         * > placeholders"
         *
         * Per **version** because the arrangement of a manual changes between
         * releases — a section added in v3 does not exist in v2 — and a
         * project-level tree would make every version's navigation describe
         * the newest one. Null means "no layout": the splicer then emits the
         * mounts in mount-path order, which is the degenerate arrangement a
         * single-component project has always had.
         */
        Schema::table('project_versions', function (Blueprint $table): void {
            $table->json('layout_json')->nullable()->after('publish_mode');
        });

        /*
         * §8.7.6's fragment and §8.7.16's references, both per build.
         *
         * 🛑 Two sources for one fragment, and the precedence is §8.7.6's
         * own: "lifted from `.docup.yaml` `nav:` **or** the generator's own
         * output". The first lands here, because the worker parses
         * `.docup.yaml` outside the sandbox (§8.4.9) and has nowhere else
         * to put the result; the second lands in the artifact at
         * `nav/nav.json`, because the generator wrote it inside the
         * sandbox. The planner prefers this column, which is what makes the
         * requirement's "or" an ordering rather than a coin toss — and
         * keeping both means an operator debugging a wrong sidebar can see
         * which one won.
         *
         * `cross_references` is collected during the ingest pass that
         * already holds every document in memory for §8.15.1's injection.
         * Capped and deduplicated there; §8.7.16 makes all of it
         * non-fatal.
         */
        Schema::table('builds', function (Blueprint $table): void {
            $table->json('nav_json')->nullable()->after('chrome_coverage');
            $table->json('cross_references')->nullable()->after('nav_json');
        });

        DataClassification::annotate('builds', [
            ['nav_json', 'content', 'content', null, '§8.7.6 nav fragment lifted from .docup.yaml; repository-written labels'],
            ['cross_references', 'content', 'content', null, '§8.7.16 outgoing /_/x/ references found in build output'],
        ]);

        /*
         * 🛑 §8.8.8, first half: "Every selector resolution MUST be recorded
         * as an append-only row."
         *
         * Append-only, so there is no `updated_at` and nothing rewrites a
         * row. The value is retrospective: when a reader reports that a page
         * changed under them, this table says which selector resolved to
         * which commit at which moment, and whether the answer moved because
         * the repository moved or because somebody edited the mount.
         *
         * `build_id` is nullable because an unresolvable selector is a
         * resolution too — recording only the successes would make the table
         * evidence for the cases that need none.
         */
        Schema::create('mount_resolutions', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_version_id');
            $table->uuidForeign('component_mount_id', index: false);
            $table->uuidForeign('component_id', index: false);

            // What was asked, copied rather than joined: the mount's selector
            // may be edited tomorrow, and a record of a decision that reads
            // the current configuration is a record of nothing.
            $table->string('selector_kind', 32);
            $table->string('selector_value', 255)->nullable();
            $table->string('mirror_fallback', 32)->nullable();

            // What it answered.
            $table->string('resolved_label', 255)->nullable();
            $table->string('resolved_ref', 255)->nullable();
            $table->char('resolved_commit_sha', 40)->nullable();
            $table->uuidForeign('build_id', nullable: true, index: false);

            // Why it answered that, for the cases where the selector and the
            // answer do not obviously match — a `mirror_label` that fell back
            // to `newest_semver_lte`, or a selector that matched nothing.
            $table->string('outcome', 48);

            $table->uuidForeign('manifest_id', nullable: true, index: false);
            $table->datetime('created_at', 3)->nullable();

            $table->index(['component_mount_id', 'id'], 'mount_resolutions_mount_index');
            $table->index(['project_version_id', 'id'], 'mount_resolutions_version_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_version_id')->references('id')->on('project_versions')->cascadeOnDelete();
        });

        /*
         * 🛑 §8.8.8, second half: "every unpublished composition change as a
         * drift event carrying the per-mount before/after ref, commit and
         * build id."
         *
         * §8.8.7 makes `publish_mode` default to `manual` for release-kind
         * versions, which is where the gate has teeth: a selector that now
         * resolves somewhere else does not change what a release serves until
         * a human approves it.
         *
         * §18.25 is the assumption — that an approval gate survives contact
         * with operators rather than everything becoming `auto`. Its
         * pre-decided consequence is the reason `auto` is one of the four
         * states rather than the absence of a row: "Keep the drift event and
         * audit record for every **automatic** publication so the evidence
         * trail survives either outcome."
         */
        Schema::create('project_version_drift_events', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_version_id');

            $table->enum('state', ['pending', 'approved', 'rejected', 'auto'])->default('pending');

            /*
             * Per-mount before/after, as §8.8.8 words it. JSON rather than a
             * child table because the document is read whole, never queried
             * by its parts, and a child table would turn one row the operator
             * reads into a join they have to assemble.
             */
            $table->json('changes_json');

            $table->uuidForeign('manifest_id', nullable: true, index: false);
            $table->uuidForeign('decided_by', nullable: true, index: false);
            $table->datetime('decided_at', 3)->nullable();
            $table->string('decision_reason', 255)->nullable();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->index(['project_version_id', 'state'], 'drift_events_version_state_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_version_id')->references('id')->on('project_versions')->cascadeOnDelete();
        });

        /*
         * 🛑 §8.7.16: "Unresolved references MUST be recorded as publish-time
         * link issues that **never fail a build and never block a publish** —
         * one repository's typo must not break another repository's build."
         *
         * Attached to the **manifest**, not to the build, and that is the
         * whole point: whether a cross-component reference resolves is a
         * property of the composition, not of the build that emitted it. The
         * same build mounted into a project that also mounts the glossary has
         * no issue; mounted alone, it has one. A build-scoped row would be
         * wrong for one of those two projects.
         *
         * Cascades with the manifest, which §10.4 makes immutable and never
         * deletes — so in practice these rows live as long as the revision
         * they describe, which is what makes "what was broken on 4 March"
         * answerable.
         */
        Schema::create('manifest_link_issues', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('manifest_id');
            $table->uuidForeign('component_id', index: false);

            // Where the reference was written, relative to the component root.
            $table->string('source_path', 512);

            // What it asked for. `target_component_key` is the component the
            // reference named, which may be one this version does not mount
            // at all — that is the commonest issue and the key is what makes
            // it legible without a join to a row that does not exist.
            $table->string('target_component_key', 100);
            $table->string('target_path', 512);

            $table->enum('kind', ['component_not_mounted', 'path_not_found', 'ambiguous'])
                ->default('path_not_found');

            $table->datetime('created_at', 3)->nullable();

            $table->index(['manifest_id', 'kind'], 'manifest_link_issues_kind_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('manifest_id')->references('id')->on('project_version_manifests')->cascadeOnDelete();
        });

        DataClassification::annotate('mount_resolutions', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['project_version_id', 'operational', 'not_applicable', null, null],
            ['component_mount_id', 'operational', 'not_applicable', null, null],
            ['component_id', 'operational', 'not_applicable', null, null],
            ['selector_kind', 'operational', 'not_applicable', null, '§8.7.5, copied at resolution time'],
            ['selector_value', 'operational', 'not_applicable', null, 'the ref, pattern, range or label asked for'],
            ['mirror_fallback', 'operational', 'not_applicable', null, '§8.7.5 fallback mode in force'],
            ['resolved_label', 'operational', 'not_applicable', null, 'version label derived per §10.2 strategy'],
            ['resolved_ref', 'content', 'content', null, 'git ref; §8.22.9 operator responsibility'],
            ['resolved_commit_sha', 'content', 'content', null, 'git provenance; §8.22.9 operator responsibility'],
            ['build_id', 'operational', 'not_applicable', null, 'null when the selector resolved to nothing'],
            ['outcome', 'operational', 'not_applicable', null, 'which branch of the selector answered'],
            ['manifest_id', 'operational', 'not_applicable', null, 'the revision this resolution was written into'],
            ['created_at', 'operational', 'not_applicable', null, '§8.8.8 append-only'],
        ]);

        DataClassification::annotate('project_version_drift_events', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['project_version_id', 'operational', 'not_applicable', null, null],
            ['state', 'operational', 'not_applicable', null, '§8.8.8 approval gate; `auto` keeps the §18.25 evidence trail'],
            ['changes_json', 'content', 'content', null, 'per-mount before/after ref, commit and build id'],
            ['manifest_id', 'operational', 'not_applicable', null, 'the revision an approval produced, once approved'],
            ['decided_by', 'operational', 'not_applicable', null, 'actor; §8.22.6 tombstoned on erasure'],
            ['decided_at', 'operational', 'not_applicable', null, null],
            ['decision_reason', 'operational', 'not_applicable', null, 'operator-written'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('manifest_link_issues', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['manifest_id', 'operational', 'not_applicable', null, null],
            ['component_id', 'operational', 'not_applicable', null, 'the component whose build wrote the reference'],
            ['source_path', 'content', 'content', null, 'path inside attacker-supplied build output'],
            ['target_component_key', 'content', 'content', null, 'component key as written in the reference'],
            ['target_path', 'content', 'content', null, 'path as written in the reference'],
            ['kind', 'operational', 'not_applicable', null, '§8.7.16 issue class'],
            ['created_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('component_mounts', [
            ['mirror_fallback', 'operational', 'not_applicable', null, '§8.7.5 fallback for `mirror_label`'],
            ['shadowing_override', 'operational', 'not_applicable', null, '🛑 §8.7.15 audited override; per mount, so not in the §20.4 registry'],
        ]);

        DataClassification::annotate('project_versions', [
            ['layout_json', 'content', 'content', null, '§8.7.6 layout tree; labels are operator-written'],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('manifest_link_issues');
        Schema::dropIfExists('project_version_drift_events');
        Schema::dropIfExists('mount_resolutions');

        /*
         * Guarded, because `down()` is run by hand far more often than it is
         * run by a deployment, and a half-applied rollback that then refuses
         * to re-run leaves an operator editing the migrations table. Each
         * column is dropped only if it is there.
         */
        self::dropIfPresent('project_versions', ['layout_json']);
        self::dropIfPresent('component_mounts', ['mirror_fallback', 'shadowing_override']);
        self::dropIfPresent('builds', ['nav_json', 'cross_references']);

        DB::table('component_mounts')
            ->whereIn('selector_kind', [
                'pinned_ref', 'track_branch', 'track_tag_pattern', 'track_semver_range', 'latest_release', 'mirror_label',
            ])
            ->update(['selector_kind' => 'latest_success']);

        DB::statement(
            'ALTER TABLE component_mounts MODIFY selector_kind ENUM('
            ."'latest_success','ref','pinned_build'"
            .") NOT NULL DEFAULT 'latest_success'"
        );

        foreach (['manifest_link_issues', 'project_version_drift_events', 'mount_resolutions'] as $table) {
            DataClassification::forget($table);
        }

        DataClassification::forget('component_mounts', ['mirror_fallback', 'shadowing_override']);
        DataClassification::forget('project_versions', ['layout_json']);
        DataClassification::forget('builds', ['nav_json', 'cross_references']);
    }

    /** @param  list<string>  $columns */
    private static function dropIfPresent(string $table, array $columns): void
    {
        $present = array_values(array_filter(
            $columns,
            static fn (string $column): bool => Schema::hasColumn($table, $column),
        ));

        if ($present === []) {
            return;
        }

        Schema::table($table, function (Blueprint $blueprint) use ($present): void {
            $blueprint->dropColumn($present);
        });
    }
};
