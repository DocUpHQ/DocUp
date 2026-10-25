<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * §8.19.3's incoming webhooks, §8.5.4's second deduplication layer, §8.6.8's
 * automation rules and §8.19.1's build schedules.
 *
 * Phase 06 created `build_requests` with `UNIQUE (integration_id,
 * delivery_id)` — §8.5.4's first layer — and nothing to point
 * `integration_id` at. This is that table, and the three others the phase
 * needs.
 */
return new class extends Migration
{
    public function up(): void
    {
        /*
         * 🛑 §8.19.3: "An **unsigned** generic webhook endpoint MUST NOT
         * exist — Read the Docs ships one and it is a build-trigger oracle."
         *
         * Which is why the secret is NOT NULL and has no default. A row in
         * this table IS the authority to trigger a build, so an integration
         * without one cannot be expressed: there is no state in which the
         * verifier has nothing to compare against and must decide what to do
         * about it.
         *
         * Envelope-encrypted rather than hashed, and this is the one place
         * §9.1.4's "stored as SHA-256 hashes" genuinely cannot apply: an HMAC
         * is verified by recomputing it, and recomputation needs the key. The
         * mitigation is the one §8.3.3 already uses for credentials — the
         * same `EnvelopeCipher`, the same KEK, the same rotation path — plus
         * the fact that the secret is generated here and never typed by a
         * human, so it is not also somebody's password.
         */
        Schema::create('webhook_integrations', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('repository_id');

            /*
             * Denormalised from the repository, because the verifier reads it
             * before it trusts anything else about the request and a join to
             * decide WHICH signature scheme to apply is a join on the
             * unauthenticated path.
             *
             * 🛑 `generic` is in the list and is not an exception to §8.19.3.
             * §8.5.3 names "generic webhook" as one of the eight trigger
             * kinds, and what §8.19.3 forbids is an **unsigned** one. A
             * generic integration carries a secret like every other row here;
             * the difference is only that nobody has written a payload
             * adapter for its provider.
             */
            $table->enum('provider', [
                'github', 'gitlab', 'bitbucket_cloud', 'bitbucket_server',
                'gitea', 'forgejo', 'generic',
            ]);

            /*
             * §11.1: "Four mutually incompatible webhook signature schemes;
             * one adapter each, one shared raw-body verifier."
             *
             * Stored rather than derived from the provider because GitLab has
             * TWO — the legacy `X-Gitlab-Token` shared secret and the
             * Standard Webhooks signing token that went GA in 19.1 — and an
             * installation pointed at a 17.x instance must be able to say so.
             */
            $table->enum('scheme', [
                'hmac_sha256_prefixed',   // GitHub, Bitbucket: `sha256=<hex>`
                'hmac_sha256_hex',        // Gitea, Forgejo, generic: bare hex
                'standard_webhooks',      // GitLab 19.1+: `v1,<base64>` over id.ts.body
                'shared_token',           // GitLab legacy: `X-Gitlab-Token`
            ]);

            // The §8.3.3 envelope, column for column, so one rotation pass
            // reaches credentials, component variables and these alike.
            $table->unsignedSmallInteger('envelope_version');
            $table->string('kek_fingerprint', 32);
            $table->binary('wrapped_key', 255, false);
            $table->binary('ciphertext', 1024, false);

            $table->enum('state', ['active', 'disabled'])->default('active');

            $table->datetime('last_delivery_at', 3)->nullable();
            $table->datetime('rotated_at', 3)->nullable();
            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            /*
             * §8.3.6: "MUST re-provision idempotently without creating
             * duplicates." One integration per repository, enforced here
             * rather than by a `firstOrCreate` that two concurrent
             * provisioning attempts would both pass.
             */
            $table->unique('repository_id', 'webhook_integrations_repository_unique');
            $table->index('kek_fingerprint');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('repository_id')->references('id')->on('repositories')->cascadeOnDelete();
        });

        /*
         * 🛑 §8.19.3's replay protection, for the providers that give us
         * nothing else: "Where no timestamp exists (Bitbucket), replay
         * protection MUST fall back to delivery-id uniqueness, and that
         * weaker guarantee MUST be documented."
         *
         * Separate from `build_requests`, which carries the same pair as
         * §8.5.4's FIRST deduplication layer, because the two answer
         * different questions at different times. `build_requests` knows
         * about deliveries that produced a build request; this table knows
         * about every delivery that verified, including the ones that
         * resolved to nothing — a push to an untracked ref, a payload for an
         * event we ignore. A replay of one of those is still a replay, and a
         * table that only remembered the interesting deliveries would admit
         * it.
         *
         * 🛑 **The weaker guarantee, stated.** A timestamp window bounds
         * replay by time and needs no state; delivery-id uniqueness bounds it
         * by this table's retention (§20: 30 days). A delivery replayed after
         * the row is purged verifies again. For a push event that means a
         * rebuild of a commit that is probably no longer the ref's head, so
         * the §8.5.2 digest short-circuit absorbs it — but it IS weaker, and
         * the operator documentation says so rather than this comment alone.
         */
        Schema::create('incoming_webhook_deliveries', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('integration_id', index: false);

            $table->string('delivery_id', 191);

            // What the provider called the event, for the operator looking at
            // a repository that is not building. Untrusted provider input, so
            // it is stored and escaped on render, never matched against.
            $table->string('event', 96)->nullable();

            $table->datetime('received_at', 3);

            $table->unique(['integration_id', 'delivery_id'], 'incoming_deliveries_unique');

            // §20's 30-day retention sweeps on this.
            $table->index('received_at');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('integration_id')->references('id')->on('webhook_integrations')->cascadeOnDelete();
        });

        /*
         * §8.5.4's SECOND deduplication layer: "ordered pre-dispatch skip
         * rules (branch/tag regex, changed-path globs, commit-message regex,
         * PR label) resolving to `skipped` and never `failed`".
         *
         * 🛑 `effect` is an enum of two, not a boolean named `skip`, because
         * the monorepo case §8.6.8 calls "the mechanism that makes a monorepo
         * feeding N projects tractable" is written the other way round: build
         * when `docs/**` changed, skip otherwise. A list that could only say
         * "skip" would need a trailing catch-all whose absence is silent.
         *
         * Ordered and first-match-wins, so `position` is unique per project.
         */
        Schema::create('build_skip_rules', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_id', index: false);

            $table->unsignedSmallInteger('position');
            $table->string('label', 120);

            $table->enum('kind', [
                'branch_tag_regex', 'changed_paths', 'commit_message_regex', 'pr_label',
            ]);

            /*
             * One nullable column per shape rather than a JSON blob, because
             * a regex and a glob list are validated differently and a single
             * `value JSON` would push that decision to read time — where the
             * only sensible response to a malformed rule is to ignore it, and
             * an ignored skip rule builds what the operator said not to.
             */
            $table->string('pattern', 512)->nullable();
            $table->json('path_globs')->nullable();

            $table->enum('effect', ['skip', 'build']);
            $table->boolean('enabled')->default(true);

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique(['project_id', 'position'], 'build_skip_rules_position_unique');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_id')->references('id')->on('projects')->cascadeOnDelete();
        });

        /*
         * §8.6.8's automation rules: "triggered by version **creation or
         * disappearance**: activate, hide, make public or private, set as
         * default, or trigger a build — filtered by branch/tag regex,
         * changed-path globs, commit message or PR label."
         *
         * Plus §8.6.15's `delete_version`, which that requirement names as an
         * automation-rule action and places on disappearance specifically:
         * "removal MUST be an automation-rule action (`delete_version`)
         * triggered by ref disappearance rather than by ref creation".
         */
        Schema::create('automation_rules', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_id', index: false);

            $table->unsignedSmallInteger('position');
            $table->string('label', 120);

            $table->enum('trigger', ['version_created', 'version_disappeared']);

            // §8.6.8's filters. All optional and ANDed: a rule with none set
            // matches every version of its trigger kind, which is the common
            // "activate everything" case written without ceremony.
            $table->enum('ref_kind', ['branch', 'tag', 'any'])->default('any');
            $table->string('ref_pattern', 512)->nullable();
            $table->json('path_globs')->nullable();
            $table->string('commit_message_pattern', 512)->nullable();
            $table->string('pr_label', 120)->nullable();

            $table->enum('action', [
                'activate', 'deactivate', 'hide', 'show',
                'make_public', 'make_private', 'set_default',
                'build', 'delete_version',
            ]);

            $table->boolean('enabled')->default(true);

            /*
             * 🛑 Rules stop at the first match by default, because §8.6.8's
             * actions are not all commutative: `set_default` followed by
             * `delete_version` leaves a project pointing at nothing. An
             * operator who genuinely wants "activate AND set default" sets
             * `continue_matching` on the first rule, which is a deliberate
             * act rather than the behaviour everybody gets by accident.
             */
            $table->boolean('continue_matching')->default(false);

            $table->datetime('last_fired_at', 3)->nullable();
            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique(['project_id', 'position'], 'automation_rules_position_unique');
            $table->index(['project_id', 'trigger', 'enabled'], 'automation_rules_trigger_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_id')->references('id')->on('projects')->cascadeOnDelete();
        });

        /*
         * §8.5.3's "native per-version cron schedule", with §8.22.13's
         * timezone rule: "Scheduled builds MUST take an IANA timezone with
         * explicit DST semantics (a 02:00 nightly build skips one day and
         * repeats another — the documentation MUST say which)."
         *
         * 🛑 What DocUp does, stated here and in the operator documentation:
         *
         *   - A wall-clock time that does NOT EXIST on a given day (the
         *     spring-forward gap) is **skipped**. 02:30 America/New_York does
         *     not occur on the second Sunday in March, and inventing an
         *     instant for it would make a "nightly at 02:30" build run at a
         *     time the operator never asked for.
         *   - A wall-clock time that occurs TWICE (the autumn-back overlap)
         *     fires **once, at the first occurrence** — the earlier UTC
         *     instant. Firing twice would mean two builds of the same commit
         *     an hour apart; §8.5.2's digest short-circuit would absorb the
         *     second, but "absorbed by a later defence" is not a semantic.
         *
         * `next_run_at` is stored in UTC like every other timestamp
         * (§8.22.13) and computed from `cron_expression` interpreted in
         * `timezone`. Storing the resolved instant rather than recomputing it
         * per tick is what makes the two rules above a property of one
         * function rather than of whenever the scheduler happened to look.
         */
        Schema::create('build_schedules', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_id', index: false);

            /*
             * Per VERSION, per §8.5.3's own words. Nullable so a project-wide
             * schedule can name the default version implicitly and keep
             * working when §8.6.14 re-points it — a nightly build of "v2.1.0"
             * that outlives v2.1.0 is a schedule nobody meant to write.
             */
            $table->uuidForeign('project_version_id', nullable: true, index: false);

            $table->string('cron_expression', 120);

            // IANA, validated on write. 64 covers the longest current zone
            // name with room to spare.
            $table->string('timezone', 64)->default('UTC');

            $table->boolean('enabled')->default(true);

            $table->datetime('last_run_at', 3)->nullable();
            $table->datetime('next_run_at', 3)->nullable();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            // The scheduler's only query: everything due, cheapest first.
            $table->index(['enabled', 'next_run_at'], 'build_schedules_due_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_id')->references('id')->on('projects')->cascadeOnDelete();
            $table->foreign('project_version_id')->references('id')->on('project_versions')->nullOnDelete();
        });

        Schema::table('projects', function (Blueprint $table): void {
            /*
             * §8.20.3's cap and policy, named in §10.4's `projects` column
             * list. They arrive HERE rather than in P32 because §17 gives
             * Phase 11 "repository-change fan-out with the preview cap", and
             * the fan-out a push produces has exactly the problem §8.20.3
             * describes: "one push to a shared component can otherwise
             * trigger previews in every consuming project."
             *
             * 🛑 One policy and one cap, used by both fan-outs. Two would
             * mean an operator who capped their previews discovering that
             * ordinary pushes were never capped at all.
             */
            $table->enum('preview_policy', ['all_dependent_versions', 'default_version_only', 'none'])
                ->default('default_version_only')
                ->after('fork_builds_enabled');

            $table->unsignedSmallInteger('preview_fanout_cap')->default(5)->after('preview_policy');
        });

        DataClassification::annotate('webhook_integrations', [
            ['id', 'pseudonymous', 'platform', null, 'surrogate key'],
            ['organisation_id', 'pseudonymous', 'platform', 'organisations', 'tenancy'],
            ['repository_id', 'pseudonymous', 'platform', 'repositories', '§8.3.6: one per repository'],
            ['provider', 'operational', 'not_applicable', null, '§11.1: which signature scheme'],
            ['scheme', 'operational', 'not_applicable', null, '§11.1: GitLab has two'],
            ['envelope_version', 'operational', 'not_applicable', null, '§8.3.3 envelope'],
            ['kek_fingerprint', 'operational', 'not_applicable', null, 'finds rows a rotation has not reached'],
            ['wrapped_key', 'secret', 'platform', null, '🛑 the DEK, wrapped'],
            ['ciphertext', 'secret', 'platform', null, '🛑 §8.19.3: the HMAC secret, sealed'],
            ['state', 'operational', 'not_applicable', null, null],
            ['last_delivery_at', 'operational', 'not_applicable', null, 'surfaces a silent webhook'],
            ['rotated_at', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('incoming_webhook_deliveries', [
            ['id', 'pseudonymous', 'platform', null, 'surrogate key'],
            ['organisation_id', 'pseudonymous', 'platform', 'organisations', 'tenancy'],
            ['integration_id', 'pseudonymous', 'platform', 'webhook_integrations', null],
            ['delivery_id', 'pseudonymous', 'platform', null, '🛑 §8.19.3: the replay key where no timestamp exists'],
            ['event', 'pseudonymous', 'platform', null, 'untrusted provider input, escaped on render'],
            ['received_at', 'operational', 'not_applicable', null, '§20: 30-day retention'],
        ]);

        DataClassification::annotate('build_skip_rules', [
            ['id', 'pseudonymous', 'platform', null, 'surrogate key'],
            ['organisation_id', 'pseudonymous', 'platform', 'organisations', 'tenancy'],
            ['project_id', 'pseudonymous', 'platform', 'projects', null],
            ['position', 'operational', 'not_applicable', null, '§8.5.4: ordered, first match wins'],
            ['label', 'pseudonymous', 'platform', null, "the operator's own name for the rule"],
            ['kind', 'operational', 'not_applicable', null, '§8.5.4: the four filter shapes'],
            ['pattern', 'pseudonymous', 'platform', null, 'a regex or a label, by kind'],
            ['path_globs', 'pseudonymous', 'platform', null, '§8.5.4: changed-path globs'],
            ['effect', 'operational', 'not_applicable', null, '🛑 skip or build; first match decides'],
            ['enabled', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('automation_rules', [
            ['id', 'pseudonymous', 'platform', null, 'surrogate key'],
            ['organisation_id', 'pseudonymous', 'platform', 'organisations', 'tenancy'],
            ['project_id', 'pseudonymous', 'platform', 'projects', null],
            ['position', 'operational', 'not_applicable', null, '§8.6.8: ordered'],
            ['label', 'pseudonymous', 'platform', null, "the operator's own name for the rule"],
            ['trigger', 'operational', 'not_applicable', null, '🛑 §8.6.8: creation or disappearance'],
            ['ref_kind', 'operational', 'not_applicable', null, '§8.6.8: branch/tag filter'],
            ['ref_pattern', 'pseudonymous', 'platform', null, '§8.6.8: branch/tag regex'],
            ['path_globs', 'pseudonymous', 'platform', null, '§8.6.8: changed-path globs'],
            ['commit_message_pattern', 'pseudonymous', 'platform', null, '§8.6.8: commit message'],
            ['pr_label', 'pseudonymous', 'platform', null, '§8.6.8: PR label'],
            ['action', 'operational', 'not_applicable', null, '🛑 §8.6.15: delete_version lives here'],
            ['enabled', 'operational', 'not_applicable', null, null],
            ['continue_matching', 'operational', 'not_applicable', null, 'first match wins unless set'],
            ['last_fired_at', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('build_schedules', [
            ['id', 'pseudonymous', 'platform', null, 'surrogate key'],
            ['organisation_id', 'pseudonymous', 'platform', 'organisations', 'tenancy'],
            ['project_id', 'pseudonymous', 'platform', 'projects', null],
            ['project_version_id', 'pseudonymous', 'platform', 'project_versions', 'null means the default version'],
            ['cron_expression', 'operational', 'not_applicable', null, '§8.5.3: native per-version cron'],
            ['timezone', 'operational', 'not_applicable', null, '🛑 §8.22.13: IANA, with stated DST semantics'],
            ['enabled', 'operational', 'not_applicable', null, null],
            ['last_run_at', 'operational', 'not_applicable', null, null],
            ['next_run_at', 'operational', 'not_applicable', null, 'UTC, resolved from the expression'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('projects', [
            ['preview_policy', 'operational', 'not_applicable', null, '§8.20.3: which versions a fan-out reaches'],
            ['preview_fanout_cap', 'operational', 'not_applicable', null, '🛑 §8.20.3: default 5'],
        ]);
    }

    public function down(): void
    {
        $projectColumns = ['preview_policy', 'preview_fanout_cap'];

        DataClassification::forget('projects', $projectColumns);

        Schema::table('projects', function (Blueprint $table) use ($projectColumns): void {
            $table->dropColumn($projectColumns);
        });

        foreach (['build_schedules', 'automation_rules', 'build_skip_rules', 'incoming_webhook_deliveries', 'webhook_integrations'] as $tableName) {
            DataClassification::forget($tableName);
            Schema::dropIfExists($tableName);
        }
    }
};
