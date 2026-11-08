<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * §8.12.22's nightly policy linter needs somewhere to remember last night.
 *
 * > "a nightly policy linter that re-validates every active rule and **alerts
 * > on reachability changes**"
 *
 * The alert is on a *change*, which is the whole reason this table exists: a
 * linter with no memory can report that rule 7 is unreachable, every night, for
 * ever. An operator who has been told the same thing thirty times has learned
 * to ignore the linter, and §8.12.22's value was the one night the message was
 * different.
 *
 * 🛑 **One row per rule, upserted** — not an append-only history. The question
 * the linter asks is "did this change since last night", which needs exactly
 * one previous observation; a history would grow with (rules × nights) and the
 * thing that reads it would still only look at the last row. What *is* kept
 * permanently is the alert itself, in §20.3's audit chain, where it is
 * tamper-evident and already has a retention policy.
 *
 * 🛑 **Proposed §10.6 addition.** §10.6 names `reader_policies` and
 * `reader_policy_rules`; it names nothing for the linter's state, because
 * §8.12.22 was written as a requirement on behaviour rather than on the schema.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('policy_lint_observations', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_id');

            /*
             * 🛑 `cascadeOnDelete`, and this is the one table where that is the
             * right answer rather than the easy one. A deleted rule has no
             * reachability to observe, and the fact of its deletion is already
             * in the audit chain from the write that deleted it — so keeping an
             * orphan observation would create a second, weaker record of the
             * same event and a nightly run reporting on a rule that no longer
             * exists.
             */
            $table->uuidForeign('rule_id', index: false);

            /*
             * §8.12.6's position, denormalised so the alert can say "rule 7"
             * without a join — and so a *moved* rule is itself a change the
             * linter notices. Reordering a policy is a reachability edit:
             * first-match-wins means position is semantics, not presentation.
             */
            $table->unsignedSmallInteger('position');

            /*
             * Whether any URL and any identity could make this rule the first
             * match. False is not an error — a shadow rule (§8.12.6) is
             * deliberately unreachable — so the **change** is the signal.
             */
            $table->boolean('reachable');

            /*
             * The position of the earliest rule whose selectors cover this
             * one's, or NULL. 🛑 The *cause*, not just the symptom: an operator
             * told "rule 7 is unreachable" has to find out why, and the answer
             * is always another rule they edited.
             */
            $table->unsignedSmallInteger('shadowed_by')->nullable();

            /*
             * Finding codes from a fixed vocabulary
             * ({@see \App\Access\PolicyFinding}), never prose. §8.22.5's rule
             * about audit payloads applies here for the same reason: this is
             * compared between runs, and free text compares as "different"
             * every time somebody improves the wording.
             */
            $table->json('findings');

            /*
             * 🛑 What the rule *admits*, as structured facts rather than a
             * score, so that a **widening** can be distinguished from a change.
             * Direction is the only thing an operator needs at 3am: a rule that
             * narrowed is somebody tightening something, and a rule that
             * widened is how documentation leaks.
             */
            $table->json('breadth');

            /*
             * The digest the comparison is actually made on. 🛑 Not a security
             * token — it is a change detector over values this table already
             * holds — so §9.1.4 does not apply and a plain SHA-256 is right:
             * the thing it protects against is a missed edit, not an attacker.
             */
            $table->binary('fingerprint', 32, true);

            $table->datetime('observed_at', 3);
            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique('rule_id', 'policy_lint_observations_rule_unique');
            $table->index(['organisation_id', 'project_id'], 'policy_lint_observations_tenant_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_id')->references('id')->on('projects')->cascadeOnDelete();
            $table->foreign('rule_id')->references('id')->on('reader_policy_rules')->cascadeOnDelete();
        });

        DataClassification::annotate('policy_lint_observations', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['project_id', 'operational', 'not_applicable', null, null],
            ['rule_id', 'operational', 'not_applicable', null, '🛑 cascade: a deleted rule has no reachability'],
            ['position', 'operational', 'not_applicable', null, '§8.12.6: position is semantics, not presentation'],
            ['reachable', 'operational', 'not_applicable', null, '🛑 §8.12.22: the change is the signal, not the value'],
            ['shadowed_by', 'operational', 'not_applicable', null, 'the cause, so an operator need not hunt for it'],
            ['findings', 'operational', 'not_applicable', null, 'fixed vocabulary; prose would differ every run'],
            ['breadth', 'operational', 'not_applicable', null, '🛑 what the rule admits, so widening is distinguishable'],
            ['fingerprint', 'operational', 'not_applicable', null, 'a change detector, not a token (§9.1.4 n/a)'],
            ['observed_at', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('policy_lint_observations');
    }
};
