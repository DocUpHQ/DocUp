<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * §8.5.19's fragment cache, §8.5.25's component variables, and the two
 * component columns §8.4 requires.
 */
return new class extends Migration
{
    public function up(): void
    {
        /*
         * 🛑 §8.5.19's lookup scope, as the PRIMARY KEY.
         *
         * > "cache per-source build output keyed by `fragment_digest =
         * > H(source_digest, env_digest, config_digest, public_env)`, 🛑
         * > **looked up only within the originating `repository_id`** — the
         * > digest is the content key, the repository row is the lookup
         * > scope, so two organisations with byte-identical sources can never
         * > share a fragment and the cache cannot act as a cross-tenant
         * > file-existence oracle."
         *
         * The repository scope is the FIRST column of the primary key rather
         * than an index beside it, and that is the point: there is no index
         * on `fragment_digest` alone, so a query that forgot the scope would
         * table-scan rather than quietly succeed. §14.2 lists the
         * cross-tenant oracle as a known trap and §19/38 records the
         * decision; `ArchitectureTest` asserts no lookup path omits it, and
         * this schema is what makes an accidental one slow and visible as
         * well as wrong.
         */
        Schema::create('fragments', function (Blueprint $table): void {
            $table->binary('repository_id', 16, true);
            $table->binary('fragment_digest', 32, true);

            $table->uuidForeign('organisation_id');

            /*
             * The build whose output this fragment IS. A hit resolves to this
             * build and the new build reuses its artifacts; §8.7.9's content
             * key already guarantees the output is project-agnostic, so the
             * reuse is safe across every project that mounts the component.
             */
            $table->uuidForeign('build_id');

            /*
             * 🛑 §8.5.19: "Any configuration referencing a secret MUST mark
             * its fragment **non-cacheable**, and no secret value may ever
             * enter a cache key."
             *
             * Stored as a fact rather than inferred at lookup time, because
             * the thing that knows a secret was used is the build that used
             * one — by the time anybody is looking the variable may have been
             * deleted, and a fragment that became cacheable retroactively
             * would start serving output built with a credential nobody has
             * any more.
             */
            $table->boolean('cacheable')->default(true);

            /* How many builds have been satisfied from this fragment. §8.8's GC reads it. */
            $table->unsignedInteger('refcount')->default(0);

            $table->datetime('last_used_at', 3)->nullable();
            $table->datetime('created_at', 3)->nullable();

            $table->primary(['repository_id', 'fragment_digest']);

            // The GC sweep: oldest unused first, within one organisation.
            $table->index(['organisation_id', 'last_used_at']);

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('build_id')->references('id')->on('builds')->cascadeOnDelete();
        });

        /*
         * Which fragments a build was assembled from. One row today, because
         * a build has one source; §8.7's composition is what makes it many,
         * and the table is shaped for that now rather than migrated then.
         */
        Schema::create('build_fragments', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('build_id');

            $table->binary('repository_id', 16, true);
            $table->binary('fragment_digest', 32, true);

            /* A hit skipped the environment and build stages; a miss created it. */
            $table->boolean('was_hit')->default(false);

            $table->datetime('created_at', 3)->nullable();

            $table->unique(['build_id', 'repository_id', 'fragment_digest'], 'build_fragments_unique');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('build_id')->references('id')->on('builds')->cascadeOnDelete();
        });

        /*
         * 🛑 §8.5.25's component-scoped build environment variables.
         *
         * > "They are scoped to the **component**, not the project, so that
         * > §8.7.10's project-agnostic rule and §8.7.9's content key both
         * > stand unchanged. Each variable carries a `public` flag: a public
         * > variable enters `public_env` and therefore the fragment digest;
         * > a secret does not, and marks the fragment non-cacheable."
         *
         * The sealed columns mirror `repository_credentials` exactly, because
         * they are sealed by the same `EnvelopeCipher` with the same rotation
         * path. A second encryption shape would be a second thing to rotate.
         */
        Schema::create('component_variables', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('component_id');

            /* The variable's name, as it appears in the build's environment. */
            $table->string('name', 64)->charset('ascii')->collation('ascii_bin');

            /*
             * 🛑 The public half is a plain column and the secret half is
             * sealed, rather than one nullable sealed column for both. A
             * public value is read on every build and shown in the UI; making
             * it travel through the cipher would mean an unseal on the hot
             * path and a UI with an unseal capability it does not need.
             */
            $table->boolean('is_public')->default(false);
            $table->text('public_value')->nullable();

            $table->unsignedSmallInteger('envelope_version')->nullable();
            $table->string('kek_fingerprint', 32)->nullable();
            $table->binary('wrapped_key', 255, false)->nullable();
            $table->binary('ciphertext', 4096, false)->nullable();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique(['component_id', 'name']);
            $table->index('kek_fingerprint');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('component_id')->references('id')->on('components')->cascadeOnDelete();
        });

        Schema::table('components', function (Blueprint $table): void {
            /*
             * §8.4.12: "Each component MUST therefore declare a
             * `build_context_mode`: `agnostic` (default) injects only the
             * installation- and component-scoped variables, so one build is
             * reusable by every project that mounts it (§7.2);
             * `project_bound` additionally injects the project-scoped
             * variables, which enter the content key and **forfeit
             * cross-project reuse**."
             */
            $table->enum('build_context_mode', ['agnostic', 'project_bound'])
                ->default('agnostic')
                ->after('default_base_url_mode');

            /*
             * 🛑 §8.4.10's legacy opt-out, on the COMPONENT where the
             * specification says project.
             *
             * A build belongs to a component and is reusable by every project
             * that mounts it (§7.2, §8.7.9). A per-project flag would either
             * change the output of a shared build — one project's setting
             * deciding another's documentation — or force itself into the
             * content key and forfeit the reuse the composition model is
             * built on. Recorded as a divergence in the build log rather than
             * taken silently.
             *
             * §20.4 covers it either way: the shell-semantics opt-out is
             * listed there as a weakening that is "per project or per
             * component", audited on change and surfaced in the settings UI,
             * rather than as an environment flag.
             */
            $table->enum('shell_semantics', ['strict', 'legacy'])
                ->default('strict')
                ->after('build_context_mode');
        });

        DataClassification::annotate('fragments', [
            ['repository_id', 'pseudonymous', 'platform', 'repositories', '🛑 §8.5.19: the lookup scope, never omitted'],
            ['fragment_digest', 'operational', 'not_applicable', null, '§8.5.19 H(source, env, config, public_env)'],
            ['organisation_id', 'pseudonymous', 'platform', 'organisations', 'tenancy'],
            ['build_id', 'pseudonymous', 'platform', 'builds', 'the build this fragment is the output of'],
            ['cacheable', 'operational', 'not_applicable', null, '🛑 §8.5.19: false once a secret was referenced'],
            ['refcount', 'operational', 'not_applicable', null, 'GC input'],
            ['last_used_at', 'operational', 'not_applicable', null, 'GC input'],
            ['created_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('build_fragments', [
            ['id', 'pseudonymous', 'platform', null, 'surrogate key'],
            ['organisation_id', 'pseudonymous', 'platform', 'organisations', 'tenancy'],
            ['build_id', 'pseudonymous', 'platform', 'builds', null],
            ['repository_id', 'pseudonymous', 'platform', 'repositories', '§8.5.19 lookup scope'],
            ['fragment_digest', 'operational', 'not_applicable', null, null],
            ['was_hit', 'operational', 'not_applicable', null, 'proves the skip in the step rows'],
            ['created_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('component_variables', [
            ['id', 'pseudonymous', 'platform', null, 'surrogate key'],
            ['organisation_id', 'pseudonymous', 'platform', 'organisations', 'tenancy'],
            ['component_id', 'pseudonymous', 'platform', 'components', null],
            ['name', 'operational', 'not_applicable', null, '§8.5.25: the name is not the secret'],
            ['is_public', 'operational', 'not_applicable', null, '🛑 §8.5.25: decides entry into public_env'],
            ['public_value', 'operational', 'not_applicable', null, '§8.5.25: declared public by its owner'],
            ['envelope_version', 'operational', 'not_applicable', null, '§9.1.7 envelope encryption'],
            ['kek_fingerprint', 'operational', 'not_applicable', null, 'which KEK wrapped this row'],
            ['wrapped_key', 'secret', 'platform', null, '🛑 §8.5.25: never returned by any API or UI'],
            ['ciphertext', 'secret', 'platform', null, '🛑 §8.5.25: never returned by any API or UI'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('components', [
            ['build_context_mode', 'operational', 'not_applicable', null, '§8.4.12; project_bound forfeits reuse'],
            ['shell_semantics', 'operational', 'not_applicable', null, '🛑 §8.4.10 legacy opt-out, audited on change'],
        ]);
    }

    public function down(): void
    {
        DataClassification::forget('components', ['build_context_mode', 'shell_semantics']);

        Schema::table('components', function (Blueprint $table): void {
            $table->dropColumn(['build_context_mode', 'shell_semantics']);
        });

        foreach (['component_variables', 'build_fragments', 'fragments'] as $table) {
            // Every column of a dropped table, which `forget()` takes as null.
            DataClassification::forget($table);

            Schema::dropIfExists($table);
        }
    }
};
