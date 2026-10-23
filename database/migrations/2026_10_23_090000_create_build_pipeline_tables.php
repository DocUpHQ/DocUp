<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The build pipeline's own tables (§8.5, §10.3).
 *
 * Phase 03 created `builds` because `manifest_builds` had no meaning without
 * it. What it could not create is everything describing *how a build happens*:
 * the trigger that asked for it, the twelve stages it moves through, and the
 * sources it pinned. Those arrive here.
 *
 * 🛑 **Two concurrency controls, and they guard different things.** The
 * `inflight` unique index on `builds` stops a second build for the same
 * version starting at all; the heartbeat lease on `build_steps` stops a second
 * *runner* picking up work the first runner is still doing. §10.3 names both
 * in one sentence, and they are not alternatives: the first is a precondition
 * checked once, the second is a claim that must survive a runner dying
 * mid-stage — "because builds outlive queue visibility timeouts", which is the
 * part that makes an ordinary queue reservation insufficient.
 */
return new class extends Migration
{
    public function up(): void
    {
        /*
         * §8.5.3: eight trigger kinds, normalised into one row. The point of
         * normalising is §8.5.4's deduplication: four ordered layers, the
         * first of which is a uniqueness constraint, and a constraint cannot
         * span eight differently-shaped entry points.
         */
        Schema::create('build_requests', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_version_id');
            $table->uuidForeign('component_id', nullable: true);

            $table->enum('trigger', [
                'webhook', 'generic_webhook', 'manual', 'api',
                'schedule', 'poll', 'repository_fanout', 'upload',
            ]);

            /*
             * 🛑 §8.5.4 layer 1: `UNIQUE (integration_id, delivery_id)`.
             *
             * Both nullable, and MySQL permits unlimited NULLs in a unique
             * index — which is exactly right here. A manual trigger has no
             * delivery id and must never collide with another manual trigger;
             * a provider redelivery has one and must collide with its first
             * attempt. One index expresses both because of how NULL behaves,
             * and a `NOT NULL DEFAULT ''` would have broken the first case.
             */
            $table->uuidForeign('integration_id', nullable: true, index: false);
            $table->string('delivery_id', 191)->nullable();

            $table->uuidForeign('requested_by', nullable: true);

            /*
             * `unchanged` and `skipped` are **terminal and not failures**
             * (§8.5.2, §8.5.4). The distinction earns its own states because
             * an operator looking at a version that is not rebuilding needs to
             * know which of three very different things happened: the inputs
             * were identical (`unchanged`), a rule they wrote said not to
             * (`skipped`), or a newer request replaced this one
             * (`superseded`). §8.5.4 is explicit that a skip "MUST resolve to
             * `skipped` and never `failed`".
             */
            $table->enum('state', [
                'queued', 'dispatched', 'completed',
                'unchanged', 'skipped', 'superseded', 'rejected', 'failed',
            ])->default('queued');

            // A stable identifier, never free text: these reach the API and
            // operator alerting exactly as `RejectionCode`'s values do.
            $table->string('outcome_identifier', 96)->nullable();

            $table->binary('plan_digest', 32, true)->nullable();
            $table->uuidForeign('build_id', nullable: true);

            /*
             * 🛑 §8.5.4: "Where a provider may truncate its changed-file
             * arrays, the system MUST treat the payload as 'everything
             * changed'." Stored rather than recomputed, because the evidence
             * for truncation is in the payload and the payload is not kept.
             * A changed-path skip rule must not be applied to a request whose
             * flag is set, and the flag is how a later phase knows.
             */
            $table->boolean('payload_truncated')->default(false);

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique(['integration_id', 'delivery_id'], 'build_requests_delivery_unique');
            $table->index(['project_version_id', 'state']);
            $table->index(['organisation_id', 'created_at']);

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_version_id')->references('id')->on('project_versions')->cascadeOnDelete();
            $table->foreign('build_id')->references('id')->on('builds')->nullOnDelete();
        });

        /*
         * §8.5.6's twelve stages, one row each, so "watch step rows advance"
         * in Phase 06's exit criteria is a query rather than a log scrape.
         */
        Schema::create('build_steps', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('build_id');

            $table->enum('stage', [
                'admit', 'plan', 'fetch', 'validate_config', 'environment', 'build',
                'collect', 'compose', 'store', 'publish', 'index', 'finalise',
            ]);

            // Display and ordering. Stored rather than derived from the enum's
            // position, because §8.5.6's order is a specified fact and an
            // enum's ordinal is an implementation detail of whoever edits it.
            $table->unsignedTinyInteger('sequence');

            $table->enum('state', ['pending', 'running', 'succeeded', 'failed', 'skipped', 'cancelled'])
                ->default('pending');

            /*
             * §8.5.16: only infrastructure-classified stages retry. The
             * attempt is in the unique key so a retry is a new row rather than
             * a mutated one — an overwritten attempt loses the evidence of why
             * the first one failed, which is the only thing that makes a
             * retried build debuggable.
             */
            $table->unsignedTinyInteger('attempt')->default(1);

            /*
             * ------------------------------------------------- heartbeat lease
             *
             * 🛑 §10.3: "claimed under a heartbeat lease, because builds
             * outlive queue visibility timeouts". A queue reservation expires
             * on a fixed clock the worker does not control; a build that takes
             * 25 minutes under a 90-second visibility timeout is redelivered
             * sixteen times. The lease inverts that: the runner holding the
             * step extends its own expiry while it is alive, and a runner that
             * dies simply stops extending.
             *
             * `lease_owner` is the runner's identity, not a user's. It exists
             * so a reclaim can be reported as "runner X died" rather than as
             * an anonymous timeout.
             */
            $table->string('lease_owner', 64)->nullable();
            $table->datetime('lease_expires_at', 3)->nullable();
            $table->unsignedInteger('lease_renewals')->default(0);

            $table->datetime('started_at', 3)->nullable();
            $table->datetime('finished_at', 3)->nullable();
            $table->integer('exit_code')->nullable();

            $table->enum('failure_class', [
                'rejected', 'config', 'source', 'user', 'contract', 'conflict',
                'timeout', 'resource', 'infra', 'cancelled', 'gate',
            ])->nullable();
            $table->string('failure_identifier', 96)->nullable();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique(['build_id', 'stage', 'attempt'], 'build_steps_attempt_unique');
            $table->index(['build_id', 'sequence']);

            // Finds the steps a reaper must reclaim without scanning.
            $table->index(['state', 'lease_expires_at']);

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('build_id')->references('id')->on('builds')->cascadeOnDelete();
        });

        /*
         * §8.5.1: "every contributing ref pinned to an immutable commit SHA by
         * `git ls-remote` **before any repository code executes**, with the
         * resolved plan recorded immutably on the build record". This is that
         * record, one row per contributing source.
         */
        Schema::create('build_sources', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('build_id');
            $table->uuidForeign('component_source_id', nullable: true);
            $table->uuidForeign('repository_id');

            // What was asked for, and what it resolved to. Both, because a
            // build reproduced six months later needs the SHA, and a human
            // reading the record needs to know it came from `main`.
            $table->string('ref', 255);
            $table->char('commit_sha', 40);
            $table->string('source_path', 255)->default('');

            /*
             * 🛑 ADR 0010 / §18.14: "a recorded 'filter honoured' flag per
             * provider". The failure this exists to catch is **silent** — a
             * server that does not support partial clone completes the clone
             * perfectly and says nothing, and the only evidence is in the
             * clone's own config. Recorded per build so that a provider which
             * stops honouring the filter after an upgrade becomes a visible
             * change in data rather than a slow increase in fetch time nobody
             * attributes to anything.
             */
            $table->boolean('filter_honoured')->nullable();
            $table->string('partial_clone_filter', 64)->nullable();
            $table->boolean('shallow')->nullable();

            $table->unsignedBigInteger('worktree_files')->nullable();
            $table->unsignedBigInteger('fetched_bytes')->nullable();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            // `uuidForeign` indexes by default (§9.1.1 applies to foreign keys),
            // so `repository_id` needs no second index here.
            $table->unique(['build_id', 'component_source_id'], 'build_sources_unique');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('build_id')->references('id')->on('builds')->cascadeOnDelete();
            $table->foreign('component_source_id')->references('id')->on('component_sources')->nullOnDelete();
            $table->foreign('repository_id')->references('id')->on('repositories')->cascadeOnDelete();
        });

        Schema::table('builds', function (Blueprint $table): void {
            // `uuidForeign` is a void macro, so these cannot be positioned with
            // `after()`. Column order is cosmetic in MySQL and not worth a
            // second migration step to control.
            $table->uuidForeign('component_source_id', nullable: true);
            $table->uuidForeign('build_request_id', nullable: true);

            /*
             * §8.5.2's digest inputs, each stored so `plan_digest` can be
             * recomputed and *disagreed with* rather than merely trusted. A
             * digest whose inputs are not recorded is a number nobody can
             * audit, and the short-circuit in §8.5.2 turns that number into a
             * decision not to build.
             */
            $table->char('config_digest', 64)->nullable()->after('plan_digest');
            $table->char('env_digest', 64)->nullable()->after('config_digest');
            $table->unsignedInteger('pipeline_version')->nullable()->after('env_digest');

            $table->enum('kind', ['full', 'preview', 'formats'])->default('full')->after('state');

            /*
             * 🛑 §10.3's `inflight` constraint: "duplicate in-flight builds are
             * impossible even inside a queue batch".
             *
             * The §18.21 idiom, verified on MySQL 8.4.11 in Phase 03 and
             * extended to VIRTUAL in Phase 04: a UNIQUE index over a
             * NULL-yielding generated column permits unlimited NULLs and
             * rejects the second non-NULL. So any number of finished builds
             * may exist for a version, and at most one may be queued or
             * running.
             *
             * VIRTUAL rather than STORED, per §18.21's Phase 04 extension:
             * `project_version_id` carries a cascading foreign key, and MySQL
             * refuses some combinations of cascade and stored generated
             * column. VIRTUAL is accepted in every case measured and costs no
             * storage.
             *
             * "even inside a queue batch" is the part that rules out an
             * application check: two jobs in one batch read the same empty
             * result and both insert. Only the database can refuse the second.
             */
            $table->tinyInteger('inflight')
                ->nullable()
                ->virtualAs("IF(state IN ('queued','running'), 1, NULL)")
                ->after('kind');

            $table->datetime('queued_at', 3)->nullable()->after('started_at');
        });

        Schema::table('builds', function (Blueprint $table): void {
            $table->unique(['project_version_id', 'kind', 'inflight'], 'builds_inflight_unique');
            $table->index('plan_digest');

            $table->foreign('component_source_id')->references('id')->on('component_sources')->nullOnDelete();
            $table->foreign('build_request_id')->references('id')->on('build_requests')->nullOnDelete();
        });

        DataClassification::annotate('build_requests', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['project_version_id', 'operational', 'not_applicable', null, null],
            ['component_id', 'operational', 'not_applicable', null, null],
            ['trigger', 'operational', 'not_applicable', null, '§8.5.3 eight normalised trigger kinds'],
            ['integration_id', 'operational', 'not_applicable', null, '§8.5.4 layer 1 deduplication'],
            ['delivery_id', 'operational', 'not_applicable', null, "the provider's own delivery identifier"],
            ['requested_by', 'pseudonymous', 'platform', 'build_requests', 'the actor who triggered the build'],
            ['state', 'operational', 'not_applicable', null, '§8.5.2, §8.5.4 terminal non-failure states'],
            ['outcome_identifier', 'operational', 'not_applicable', null, 'stable identifier; reaches the API'],
            ['plan_digest', 'operational', 'not_applicable', null, '§8.5.2'],
            ['build_id', 'operational', 'not_applicable', null, null],
            ['payload_truncated', 'operational', 'not_applicable', null, '🛑 §8.5.4: a truncated payload means everything changed'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('build_steps', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['build_id', 'operational', 'not_applicable', null, null],
            ['stage', 'operational', 'not_applicable', null, '§8.5.6 the twelve stages'],
            ['sequence', 'operational', 'not_applicable', null, null],
            ['state', 'operational', 'not_applicable', null, null],
            ['attempt', 'operational', 'not_applicable', null, '§8.5.16 retries are new rows, not mutations'],
            ['lease_owner', 'operational', 'not_applicable', null, '🛑 §10.3 heartbeat lease: the runner, never a user'],
            ['lease_expires_at', 'operational', 'not_applicable', null, '🛑 §10.3 heartbeat lease'],
            ['lease_renewals', 'operational', 'not_applicable', null, 'evidence the runner was alive'],
            ['started_at', 'operational', 'not_applicable', null, null],
            ['finished_at', 'operational', 'not_applicable', null, null],
            ['exit_code', 'operational', 'not_applicable', null, '§8.5.15: 183 is a voluntary cancel'],
            ['failure_class', 'operational', 'not_applicable', null, '§8.5.15 typed failure classes'],
            ['failure_identifier', 'operational', 'not_applicable', null, 'stable identifier (§8.19.15)'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('build_sources', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['build_id', 'operational', 'not_applicable', null, null],
            ['component_source_id', 'operational', 'not_applicable', null, null],
            ['repository_id', 'operational', 'not_applicable', null, null],
            ['ref', 'operational', 'not_applicable', null, '§8.5.1 what was asked for'],
            ['commit_sha', 'operational', 'not_applicable', null, '§8.5.1 what it pinned to, before any code ran'],
            ['source_path', 'operational', 'not_applicable', null, '§8.4.1 discovery root'],
            ['filter_honoured', 'operational', 'not_applicable', null, '🛑 ADR 0010 / §18.14: the silent fallback is only visible here'],
            ['partial_clone_filter', 'operational', 'not_applicable', null, 'ADR 0010'],
            ['shallow', 'operational', 'not_applicable', null, 'ADR 0010: the flag actually doing the work'],
            ['worktree_files', 'operational', 'not_applicable', null, '§18.14 asks for the working-tree file count'],
            ['fetched_bytes', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('builds', [
            ['component_source_id', 'operational', 'not_applicable', null, null],
            ['build_request_id', 'operational', 'not_applicable', null, null],
            ['config_digest', 'operational', 'not_applicable', null, '§8.5.2 plan digest input'],
            ['env_digest', 'operational', 'not_applicable', null, '§8.5.2 plan digest input; includes the image digest (§8.5.14)'],
            ['pipeline_version', 'operational', 'not_applicable', null, '§8.5.2 plan digest input'],
            ['kind', 'operational', 'not_applicable', null, null],
            ['inflight', 'derived', 'not_applicable', null, '🛑 §10.3/§18.21: at most one queued or running build per version'],
            ['queued_at', 'operational', 'not_applicable', null, '§8.5.23 queue position'],
        ]);
    }

    public function down(): void
    {
        Schema::table('builds', function (Blueprint $table): void {
            $table->dropForeign(['component_source_id']);
            $table->dropForeign(['build_request_id']);
            $table->dropUnique('builds_inflight_unique');
            $table->dropIndex(['plan_digest']);
            $table->dropColumn([
                'component_source_id', 'build_request_id', 'config_digest',
                'env_digest', 'pipeline_version', 'kind', 'inflight', 'queued_at',
            ]);
        });

        Schema::dropIfExists('build_sources');
        Schema::dropIfExists('build_steps');
        Schema::dropIfExists('build_requests');

        foreach (['build_sources', 'build_steps', 'build_requests'] as $table) {
            DataClassification::forget($table);
        }

        DataClassification::forget('builds', [
            'component_source_id', 'build_request_id', 'config_digest',
            'env_digest', 'pipeline_version', 'kind', 'inflight', 'queued_at',
        ]);
    }
};
