<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * §8.6's write side: ref sync, the two channels, the comparator, and the
 * 301 a renamed slug leaves behind.
 *
 * Phase 03 created `project_versions` with §8.6.2's four axes and §8.6.12's
 * language already on it. What it could not create was anything about where
 * a version CAME FROM, because nothing discovered refs until Phase 06 and
 * nothing synchronised them until now.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('projects', function (Blueprint $table): void {
            /*
             * 🛑 §8.6.4 and §8.6.5 share this column, and that sharing is
             * the requirement: "the **same** comparator MUST drive both this
             * derivation and the §8.6.5 flyout order, so a project tagging
             * `1.0rc1` or `1.0.post1` cannot get one order in its version
             * list and another in its `stable` pointer."
             */
            $table->enum('version_comparator', ['semver', 'pep440', 'calver', 'alphabetical'])
                ->default('semver')
                ->after('versioning_scheme');

            /*
             * §8.6.5's "separate per-project toggle for whether `latest` and
             * `stable` are pinned to the top of the list or sorted in
             * place". Default true, because a reader looking for the current
             * documentation looks at the top.
             */
            $table->boolean('pin_channels_to_top')->default(true)->after('version_comparator');

            /*
             * §8.6.4's step 1 for each channel: "an explicit per-project
             * override". Null means "derive", not "none" — §8.6.4's step 5
             * says no `stable` at all is a valid outcome of the derivation,
             * and the two states are different: an override of null is a
             * project that has not chosen, and a derivation that produced
             * nothing is a project with no release tags.
             */
            $table->uuidForeign('stable_version_id', nullable: true, index: false);
            $table->uuidForeign('latest_version_id', nullable: true, index: false);

            /*
             * 🛑 The DERIVED pointers, stored, and separate from the
             * overrides above. Four columns where two would look like
             * enough, because the two pairs answer different questions:
             * `stable_version_id` is what an operator chose and must survive
             * a sync that would have derived something else;
             * `resolved_stable_version_id` is what `stable` currently points
             * at, override included.
             *
             * Stored rather than computed for §8.6.14's reason about the
             * default version: §8.9.7's empty-path redirect and §8.11.5's
             * 404 chain read these on the serving path, and deriving them
             * there would put a comparator and a version list in front of
             * every request that omits a version.
             */
            $table->uuidForeign('resolved_stable_version_id', nullable: true, index: false);
            $table->uuidForeign('resolved_latest_version_id', nullable: true, index: false);

            /*
             * 🛑 §8.6.3, and §10.4 names this column: "A newly discovered
             * version MUST inherit `private` whenever the project has ever
             * had a non-public access rule, so that making a project public
             * can never retroactively expose a version, and a new branch on
             * a private project is never born public."
             *
             * **Ever**, which is why this is a latch rather than a reading of
             * the current visibility. A project that was private in March and
             * is public today still has readers who were admitted under the
             * old rule and content written on that understanding; a branch
             * created tomorrow must not be born public because somebody
             * flipped a switch in between. Nothing in the application clears
             * it.
             */
            $table->boolean('has_ever_been_guarded')->default(false)->after('visibility');
        });

        Schema::table('project_versions', function (Blueprint $table): void {
            /*
             * Where this version came from. Null for a version created by
             * hand or by the upload API (§8.19.6), which is a real case: an
             * installation in §8.1.7's hosting-only mode has versions and no
             * refs at all.
             */
            $table->string('ref_name', 255)->nullable()->after('slug');
            $table->enum('ref_kind', ['branch', 'tag'])->nullable()->after('ref_name');

            /*
             * The SHA the ref pointed at when it was last seen. Not the
             * build's commit — §8.5.1 pins that per build — but the sync's
             * view, which is what tells the next sync whether anything moved.
             */
            $table->char('ref_commit_sha', 40)->nullable()->after('ref_kind');
            $table->datetime('ref_seen_at', 3)->nullable()->after('ref_commit_sha');

            /*
             * 🛑 §8.6.15: "the version MUST be deactivated rather than
             * silently deleted, its URLs MUST continue to resolve until an
             * operator or an automation rule removes it".
             *
             * A timestamp rather than a flag, because the automation rule
             * that may later delete it (§8.6.8's `delete_version`) wants to
             * know how long ago the ref went, and because "deactivated
             * because the branch was deleted" and "deactivated because
             * somebody deactivated it" are different facts that `active`
             * alone cannot tell apart.
             */
            $table->datetime('ref_disappeared_at', 3)->nullable()->after('ref_seen_at');

            /*
             * §8.6.7's "wipe version" action: "discards artifacts while
             * retaining the version row". The row stays so its URLs keep
             * resolving to a 404 that knows what it is rather than to the
             * nothing a deleted row gives.
             */
            $table->datetime('wiped_at', 3)->nullable()->after('ref_disappeared_at');

            $table->index(['project_id', 'ref_kind']);
        });

        /*
         * 🛑 §8.6.6: "a renamed slug MUST leave a working 301 behind it."
         *
         * A table rather than a `redirect_rules` row, and the §8.11.1 order
         * is why: user rules are evaluated after "implicit redirects", and a
         * slug rename is an implicit redirect — it is a fact about the
         * version's identity, not a rule somebody wrote. Putting it in
         * `redirect_rules` would also let an operator delete it by tidying
         * their redirects, which is exactly the URL breakage the requirement
         * exists to prevent.
         *
         * Keyed by (project, language, slug) to match
         * `project_versions_slug_unique`, because §8.6.12 makes `/en/v2/` and
         * `/ja/v2/` two different versions that share a slug by design.
         */
        Schema::create('project_version_slug_history', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_id');
            $table->uuidForeign('project_version_id');

            $table->char('language', 5)->charset('ascii')->collation('ascii_bin');
            $table->string('slug', 80);

            $table->datetime('created_at', 3)->nullable();

            /*
             * 🛑 One row per (project, language, slug) — a former slug points
             * at exactly one version. Reusing a freed slug for a NEW version
             * therefore has to displace the history row rather than sit
             * beside it, or one URL would have two meanings and the resolver
             * would pick whichever the database returned first.
             */
            $table->unique(['project_id', 'language', 'slug'], 'version_slug_history_unique');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_id')->references('id')->on('projects')->cascadeOnDelete();
            $table->foreign('project_version_id')->references('id')->on('project_versions')->cascadeOnDelete();
        });

        DataClassification::annotate('projects', [
            ['version_comparator', 'operational', 'not_applicable', null, '§8.6.4 and §8.6.5 share it'],
            ['pin_channels_to_top', 'operational', 'not_applicable', null, '§8.6.5 flyout order'],
            ['stable_version_id', 'pseudonymous', 'platform', 'project_versions', '§8.6.4 step 1: the override'],
            ['latest_version_id', 'pseudonymous', 'platform', 'project_versions', '§8.6.4 step 1: the override'],
            ['resolved_stable_version_id', 'pseudonymous', 'platform', 'project_versions', '§8.6.4: what stable points at'],
            ['resolved_latest_version_id', 'pseudonymous', 'platform', 'project_versions', '§8.6.4: what latest points at'],
            ['has_ever_been_guarded', 'operational', 'not_applicable', null, '🛑 §8.6.3: a latch, never cleared'],
        ]);

        DataClassification::annotate('project_versions', [
            ['ref_name', 'pseudonymous', 'platform', null, '§8.6.1: the branch or tag this came from'],
            ['ref_kind', 'operational', 'not_applicable', null, '§8.6.4 prefers tags for stable'],
            ['ref_commit_sha', 'pseudonymous', 'platform', null, 'the SHA the ref pointed at when last seen'],
            ['ref_seen_at', 'operational', 'not_applicable', null, '§8.6.15 disappearance detection'],
            ['ref_disappeared_at', 'operational', 'not_applicable', null, '🛑 §8.6.15: deactivated, never deleted'],
            ['wiped_at', 'operational', 'not_applicable', null, '§8.6.7: artifacts gone, row retained'],
        ]);

        DataClassification::annotate('project_version_slug_history', [
            ['id', 'pseudonymous', 'platform', null, 'surrogate key'],
            ['organisation_id', 'pseudonymous', 'platform', 'organisations', 'tenancy'],
            ['project_id', 'pseudonymous', 'platform', 'projects', null],
            ['project_version_id', 'pseudonymous', 'platform', 'project_versions', 'the 301 target'],
            ['language', 'operational', 'not_applicable', null, '§8.6.12: part of the key'],
            ['slug', 'pseudonymous', 'platform', null, '🛑 §8.6.6: the former slug, kept so its URLs work'],
            ['created_at', 'operational', 'not_applicable', null, null],
        ]);
    }

    public function down(): void
    {
        DataClassification::forget('project_version_slug_history');
        Schema::dropIfExists('project_version_slug_history');

        DataClassification::forget('project_versions', [
            'ref_name', 'ref_kind', 'ref_commit_sha', 'ref_seen_at', 'ref_disappeared_at', 'wiped_at',
        ]);

        Schema::table('project_versions', function (Blueprint $table): void {
            /*
             * No explicit `dropIndex`. MySQL removes an index when any of
             * its columns is dropped, so naming it here is both redundant
             * and wrong — the drop runs second and finds nothing, which
             * fails the rollback half way through and leaves the schema in
             * a state neither migration describes. Found by running it.
             */
            $table->dropColumn([
                'ref_name', 'ref_kind', 'ref_commit_sha', 'ref_seen_at', 'ref_disappeared_at', 'wiped_at',
            ]);
        });

        $columns = [
            'version_comparator', 'pin_channels_to_top', 'stable_version_id', 'latest_version_id',
            'resolved_stable_version_id', 'resolved_latest_version_id', 'has_ever_been_guarded',
        ];

        DataClassification::forget('projects', $columns);

        Schema::table('projects', function (Blueprint $table) use ($columns): void {
            $table->dropColumn($columns);
        });
    }
};
