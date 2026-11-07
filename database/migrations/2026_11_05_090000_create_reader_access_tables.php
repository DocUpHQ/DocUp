<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Carbon\CarbonImmutable;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * §8.12.6's reader policies, §8.12.23's `deny_status` and §20.3's decision log
 * (§10.4, §10.6).
 *
 * 🛑 **The access lattice is not created here, and that is the design.** §17's
 * Phase 21 entry says mount-level and component-level privacy are modelled
 * "**from the start**, which is why the lattice columns exist on tables created
 * in P03 and P04 rather than being added here". All four are already present —
 * `projects.visibility` (P02), `project_versions.visibility` (P04),
 * `components.min_access` / `component_mounts.min_access_snapshot` (P04) and
 * `domain_mounts.mount_exposure` (P04) — so this migration adds the *policy*
 * layer that reads them and nothing that retrofits a privacy column onto a live
 * serving path.
 *
 * What it does add is the three project columns §10.4 lists and the P04
 * migration deliberately left out, naming them: "`deny_status`, `authz_epoch`
 * and others. They are deliberately absent … each belongs to the phase that
 * gives it meaning."
 */
return new class extends Migration
{
    /**
     * Days of `access_decisions` partitions created up front.
     *
     * §20.3 retains denials and challenges for 90 days and purges by `DROP
     * PARTITION`, so the maintenance job has to create tomorrow's partition
     * every day either way. 60 days of runway means a stalled scheduler
     * degrades over two months rather than over two days — and `pmax` below
     * means it degrades rather than failing.
     */
    private const DAYS_AHEAD = 60;

    public function up(): void
    {
        Schema::table('projects', function (Blueprint $table): void {
            /*
             * 🛑 §8.12.23: "A per-project `deny_status='403'` MUST be available
             * for **authenticated** principals only, never anonymous, because
             * the leak register, audit reason codes and edge cacheability all
             * key off this distinction."
             *
             * The column is the project's *preference*; the anonymous-never
             * half of the rule cannot be a column at all, because it depends on
             * the request. It lives in `EffectiveAccess` where the request is,
             * with a test naming this requirement.
             *
             * 404 by default, which §8.12.23 makes the default for every
             * unauthorised or unresolvable resource.
             */
            $table->enum('deny_status', ['404', '403'])->default('404')->after('visibility');

            /*
             * §10.8's two remaining epochs, both owned by this phase.
             *
             * `authz_epoch` is bumped by "policy, rule, binding, visibility
             * change" and keys the decision caches; `policy_generation` is
             * bumped by a policy write and gates search. They are separate
             * counters because they fail differently: §10.8 gives `authz_epoch`
             * a one-request staleness bound and `policy_generation` "fail
             * closed", and one counter cannot have two behaviours.
             *
             * Unsigned big integers rather than timestamps. An epoch is
             * compared for equality and ordering, never read as a time, and a
             * monotonic counter cannot go backwards when a clock does.
             */
            $table->unsignedBigInteger('authz_epoch')->default(0)->after('routing_epoch');
            $table->unsignedBigInteger('policy_generation')->default(0)->after('authz_epoch');
        });

        /*
         * 🛑 §8.12.8: "`reader_policies` is keyed on `project_id` and a
         * collection holds no policy of its own (§10.1, §10.6), so a widening
         * inheritance flag would have nothing to inherit from and would exist
         * only as a way to defeat this requirement."
         *
         * So the UNIQUE on `project_id` is load-bearing: one policy per
         * project, no policy anywhere else, and no second row for a collection
         * to point at.
         */
        Schema::create('reader_policies', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_id');

            /*
             * 🛑 Both are single-valued enums, and that is on purpose rather
             * than an oversight. §10.6 writes them as `ENUM('closed') DEFAULT
             * 'closed'` and `ENUM('deny') DEFAULT 'deny'`: the column exists so
             * the invariant is *visible* in the schema and in every dump, while
             * the database refuses to store the other value. A boolean named
             * `fail_open` would be one `UPDATE` away from a fail-open
             * installation; this is one migration away, which is a review.
             */
            $table->enum('fail_mode', ['closed'])->default('closed');
            $table->enum('default_effect', ['deny'])->default('deny');

            /*
             * 🛑 §8.12.7's one escape from the satisfiability invariant: "unless
             * it is literally the public terminal or the project has explicitly
             * enabled network-only access (UI-flagged weak, audited)".
             *
             * Default false, so an IP allowlist cannot stand in for
             * authentication unless somebody deliberately said it may.
             */
            $table->boolean('allow_network_only_access')->default(false);

            /*
             * The policy's own epoch (§10.6). Distinct from the project's
             * `authz_epoch`: this one identifies *which* policy a cached
             * decision or a minted grant was made under, so a grant can be
             * refused by comparing it rather than by purging anything.
             */
            $table->unsignedBigInteger('epoch')->default(0);

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique('project_id', 'reader_policies_project_unique');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_id')->references('id')->on('projects')->cascadeOnDelete();
        });

        Schema::create('reader_policy_rules', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('policy_id');

            /*
             * 🛑 §8.12.6: "an ordered, **first-match-wins** list of rules".
             * UNIQUE for the same reason §8.11.2's redirect positions are
             * unique — a tie broken by insertion order is an ordering nobody
             * chose, and here the thing it decides is who may read.
             */
            $table->unsignedSmallInteger('position');

            /** The operator's own name for the rule, shown by §8.12.25's simulator. */
            $table->string('label', 120);

            /*
             * §8.12.6's "version selector and optional normalised path prefix".
             *
             * JSON because a selector is a small structure — a kind and a value
             * — and §8.11.4's lesson applies in reverse here: §8.12.9 forbids
             * regex path matching outright ("it either destroys the edge fast
             * path or becomes an enumeration oracle"), so these are literal
             * prefixes and a column per shape would be four nullable columns
             * and a CHECK constraint.
             */
            $table->json('version_selector');
            $table->json('path_patterns');

            $table->enum('effect', ['allow', 'deny']);

            /*
             * 🛑 §8.12.6's "schema-validated two-level boolean requirement tree
             * over leaves `{binding}`, `{gate}`, `{share}`, `{bearer}`,
             * `{public}`".
             *
             * Two levels, not arbitrary depth, and the bound is the point: an
             * operator has to be able to read the rule and say who it lets in.
             * §8.12.7's satisfiability invariant is decided over this column at
             * write time, which is only tractable because the depth is bounded.
             */
            $table->json('requirement');

            /*
             * How long a grant satisfied by this rule may live (§8.12.11's `exp
             * ≤ 10 minutes`). Nullable means "the installation default"; the
             * ceiling is enforced in the application, where the reason can be
             * stated, and P22 mints against it.
             */
            $table->unsignedSmallInteger('grant_ttl_seconds')->nullable();

            /*
             * 🛑 §9.3.2's third input, stored per rule. `public` is permitted
             * only on a rule whose requirement is the public terminal —
             * refused at write time otherwise — because this column is what
             * `CachePolicy` reads as `rulePubliclyCacheable`, and a rule that
             * demanded a credential while declaring itself publicly cacheable
             * would put a private response in a shared cache.
             */
            $table->enum('cache_mode', ['private', 'public'])->default('private');

            /*
             * §8.6.2 keeps `listed` on the version; this overrides it for
             * readers this rule admits, so a version hidden from the public
             * flyout can appear in a member's. Nullable means "no override".
             */
            $table->boolean('listed_override')->nullable();

            /*
             * 🛑 A shadow rule is evaluated and recorded and never enforced
             * (§8.12.22's "nightly policy linter … alerts on reachability
             * changes" needs somewhere to try a rule before it bites). The
             * default is false in both directions that matter: a new rule
             * enforces, and a shadow rule can never allow.
             */
            $table->boolean('shadow')->default(false);

            $table->datetime('not_before', 3)->nullable();
            $table->datetime('not_after', 3)->nullable();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique(['policy_id', 'position'], 'reader_policy_rules_position_unique');

            /*
             * Every rule for a policy, in position order, from one covering
             * index — the same shape §8.11.2's rules are read in, and for the
             * same reason: first-match-wins is evaluated in PHP over the whole
             * ordered set, so the query must be one.
             */
            $table->index(['policy_id', 'position'], 'reader_policy_rules_evaluation_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('policy_id')->references('id')->on('reader_policies')->cascadeOnDelete();
        });

        DB::statement($this->accessDecisionsDdl());

        DataClassification::annotate('projects', [
            ['deny_status', 'operational', 'not_applicable', null, '🛑 §8.12.23: 403 for authenticated principals only'],
            ['authz_epoch', 'operational', 'not_applicable', null, '§10.8: policy, rule, binding, visibility change'],
            ['policy_generation', 'operational', 'not_applicable', null, '§10.8: policy write; gates search, fails closed'],
        ]);

        DataClassification::annotate('reader_policies', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['project_id', 'operational', 'not_applicable', null, '🛑 §8.12.8: the only key a policy has'],
            ['fail_mode', 'operational', 'not_applicable', null, "🛑 §10.6: ENUM('closed'), one value by design"],
            ['default_effect', 'operational', 'not_applicable', null, "🛑 §10.6: ENUM('deny'), one value by design"],
            ['allow_network_only_access', 'operational', 'not_applicable', null, '🛑 §8.12.7: UI-flagged weak, audited'],
            ['epoch', 'operational', 'not_applicable', null, '§10.8: which policy a grant was minted under'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('reader_policy_rules', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['policy_id', 'operational', 'not_applicable', null, null],
            ['position', 'operational', 'not_applicable', null, '🛑 §8.12.6 first-match-wins ordering'],
            ['label', 'content', 'content', null, "the operator's own name for the rule"],
            ['version_selector', 'operational', 'not_applicable', null, '§8.12.6 version selector'],
            ['path_patterns', 'content', 'content', null, '🛑 §12.3: relative to a component mount'],
            ['effect', 'operational', 'not_applicable', null, 'allow or deny'],
            ['requirement', 'operational', 'not_applicable', null, '🛑 §8.12.6 two-level tree; §8.12.7 invariant'],
            ['grant_ttl_seconds', 'operational', 'not_applicable', null, '§8.12.11: exp ≤ 10 minutes'],
            ['cache_mode', 'operational', 'not_applicable', null, '🛑 §9.3.2 third input to the public check'],
            ['listed_override', 'operational', 'not_applicable', null, '§8.6.2 listed, for readers this rule admits'],
            ['shadow', 'operational', 'not_applicable', null, '🛑 evaluated and recorded, never enforced'],
            ['not_before', 'operational', 'not_applicable', null, null],
            ['not_after', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('access_decisions', [
            ['id', 'operational', 'not_applicable', 'access_decisions', null],
            ['id_text', 'derived', 'not_applicable', 'access_decisions', 'generated view of id'],
            ['decided_on', 'operational', 'not_applicable', 'access_decisions', 'the partition key'],
            ['decided_at', 'operational', 'not_applicable', 'access_decisions', null],
            ['organisation_id', 'operational', 'not_applicable', 'access_decisions', 'no FK: partitioned InnoDB cannot carry one'],
            ['project_id', 'operational', 'not_applicable', 'access_decisions', 'no FK: see organisation_id'],
            ['version_id', 'operational', 'not_applicable', 'access_decisions', 'no FK: see organisation_id'],
            ['mount_id', 'operational', 'not_applicable', 'access_decisions', 'no FK: see organisation_id'],
            ['outcome', 'operational', 'not_applicable', 'access_decisions', 'allow, deny or challenge'],
            ['surface', 'operational', 'not_applicable', 'access_decisions', '§8.12.21: proxy, download, search, addons'],
            ['status', 'operational', 'not_applicable', 'access_decisions', '🛑 §8.12.23: the status actually sent'],
            ['reason_code', 'operational', 'not_applicable', 'access_decisions', 'stable code, never free text'],
            ['rule_id', 'operational', 'not_applicable', 'access_decisions', 'the first-match rule, when one matched'],
            ['required_level', 'operational', 'not_applicable', 'access_decisions', '§12.3 lattice: what the resource demanded'],
            ['established_level', 'operational', 'not_applicable', 'access_decisions', '§12.3 lattice: what the reader had'],
            ['satisfied_by', 'operational', 'not_applicable', 'access_decisions', '§8.12.17 leaf kind, when one satisfied'],
            // 🛑 Pseudonymous, like `audit_events.actor_id`. §20.3 gives a raw
            // IP a 7-day retention in `security_events` and calls that "the
            // only place a raw IP exists"; this column holds a keyed digest of
            // a session handle, never an address and never an identity.
            ['subject_hash', 'pseudonymous', 'not_applicable', 'access_decisions', '🛑 keyed digest; never an address or an identity'],
            ['aggregate_key', 'pseudonymous', 'not_applicable', 'access_decisions', '🛑 §20.3: NULL for a denial, set for an allow'],
            ['occurrences', 'operational', 'not_applicable', 'access_decisions', '§20.3: one row per session, version and hour'],
            ['authz_epoch', 'operational', 'not_applicable', 'access_decisions', 'the epoch the decision was made under'],
        ]);
    }

    public function down(): void
    {
        DataClassification::forget('access_decisions');
        DataClassification::forget('reader_policy_rules');
        DataClassification::forget('reader_policies');
        DataClassification::forget('projects', ['deny_status', 'authz_epoch', 'policy_generation']);

        Schema::dropIfExists('access_decisions');
        Schema::dropIfExists('reader_policy_rules');
        Schema::dropIfExists('reader_policies');

        Schema::table('projects', function (Blueprint $table): void {
            $table->dropColumn(['deny_status', 'authz_epoch', 'policy_generation']);
        });
    }

    /**
     * §20.3's decision log: day-partitioned, no foreign keys.
     *
     * 🛑 **Two row shapes in one table, separated by one nullable column.**
     * §20.3 retains "denials, challenges" for 90 days as individual rows and
     * "aggregated allows" as "one row per session, version and hour". A denial
     * is evidence and each one matters; an allow is volume — a reader opening a
     * sixty-asset page authorises sixty times, and sixty rows per page view is
     * the shape that makes an access log unaffordable and then switched off.
     *
     * So `aggregate_key` is a digest of (subject, version, hour) for an allow
     * and **NULL** for a denial or a challenge, and the UNIQUE key does the
     * aggregation: MySQL permits any number of NULLs in a unique index, so
     * denials each get their own row while allows collapse onto one that an
     * upsert increments. No branch, no second table, and no way to write an
     * allow that escapes the aggregation.
     *
     * The partition column is in the primary key and in the unique key because
     * MySQL requires every unique key on a partitioned table to contain the
     * partitioning column (§10.6's own note, learned on `audit_events`).
     */
    private function accessDecisionsDdl(): string
    {
        return sprintf(
            <<<'SQL'
            CREATE TABLE `access_decisions` (
              `id`                BINARY(16)       NOT NULL,
              `id_text`           CHAR(36)         AS (BIN_TO_UUID(`id`)) VIRTUAL,
              `decided_on`        DATE             NOT NULL,
              `decided_at`        DATETIME(3)      NOT NULL,
              `organisation_id`   BINARY(16)       NULL,
              `project_id`        BINARY(16)       NULL,
              `version_id`        BINARY(16)       NULL,
              `mount_id`          BINARY(16)       NULL,
              `outcome`           ENUM('allow', 'deny', 'challenge') NOT NULL,
              `surface`           ENUM('proxy', 'download', 'search', 'addons') NOT NULL,
              `status`            SMALLINT UNSIGNED NOT NULL,
              `reason_code`       VARCHAR(64)      NOT NULL,
              `rule_id`           BINARY(16)       NULL,
              `required_level`    ENUM('public', 'authenticated', 'members', 'restricted') NOT NULL,
              `established_level` ENUM('public', 'authenticated', 'members', 'restricted') NOT NULL,
              `satisfied_by`      ENUM('binding', 'gate', 'share', 'bearer', 'public') NULL,
              `subject_hash`      BINARY(32)       NULL,
              `aggregate_key`     BINARY(16)       NULL,
              `occurrences`       INT UNSIGNED     NOT NULL DEFAULT 1,
              `authz_epoch`       BIGINT UNSIGNED  NOT NULL DEFAULT 0,
              PRIMARY KEY (`id`, `decided_on`),
              UNIQUE KEY `access_decisions_aggregate_unique` (`decided_on`, `aggregate_key`),
              KEY `access_decisions_project_index` (`project_id`, `decided_on`),
              KEY `access_decisions_outcome_index` (`outcome`, `decided_on`),
              KEY `access_decisions_rule_index` (`rule_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
            PARTITION BY RANGE COLUMNS(`decided_on`) (
            %s
            )
            SQL,
            $this->partitionList(),
        );
    }

    /**
     * Daily partitions, plus the catch-all §16 requires.
     *
     * 🛑 `pmax` for the same reason `audit_events` has one: without a
     * `MAXVALUE` partition an insert past the last boundary **fails**, and the
     * day daily maintenance stops running would be the day every access
     * decision starts erroring. A decision that cannot be recorded must not
     * become a decision that cannot be made, so the catch-all turns an outage
     * into one fat partition and an alert.
     */
    private function partitionList(): string
    {
        $partitions = [];
        $day = CarbonImmutable::now('UTC')->startOfDay();

        for ($i = 0; $i < self::DAYS_AHEAD; $i++) {
            $boundary = $day->addDay();

            $partitions[] = sprintf(
                "  PARTITION `p%s` VALUES LESS THAN ('%s')",
                $day->format('Y_m_d'),
                $boundary->format('Y-m-d'),
            );

            $day = $boundary;
        }

        $partitions[] = '  PARTITION `pmax` VALUES LESS THAN (MAXVALUE)';

        return implode(",\n", $partitions);
    }
};
