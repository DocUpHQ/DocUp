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
 * §10.7's `search_documents`, the scope table that filters it, and the two
 * generation counters §8.12.21 compares.
 *
 * ## 🛑 Why there are two tables and not one
 *
 * §8.16.5 and §8.16.8 pull in opposite directions and both are 🛑.
 *
 * §8.16.5: "Search documents MUST be keyed to `build_id` and a path **relative
 * to the build**, never to an absolute URL … A reused build is then indexed
 * **once** and is searchable from every project that mounts it."
 *
 * §8.16.8: "Every filterable attribute MUST be declared in v1 — project,
 * version, language, visibility scope, build generation."
 *
 * A single table cannot satisfy both. Put `project_id` on the document row and
 * a build mounted by three projects is three copies of every section — which is
 * exactly what §8.16.5 forbids, and the copies then disagree the moment one
 * project republishes. Leave the project off and there is nothing to filter.
 *
 * So the document row is keyed to the **build** and carries the text, and
 * `search_mount_scopes` carries one row per (project version, mount) saying
 * which build that mount exposes, under which visibility scope, in which
 * language, at which generation. The match runs on the first table and the
 * mandatory filter is a join to the second — which is literally §8.16.6's
 * measured shape: "a `MATCH … AGAINST` with a `build_id`/scope predicate".
 *
 * 🛑 That is also the only place §8.12.21's "every search document MUST carry a
 * visibility scope identifier as a mandatory server-side filter" can honestly
 * live. A build reused by a public project and a `members` project has **two**
 * scopes; a scalar on the shared row could only ever be wrong for one of them,
 * and wrong in the disclosing direction half the time.
 *
 * ## 🛑 Why `search_documents` carries the one `AUTO_INCREMENT`
 *
 * §9.1.3 and §8.16.11: InnoDB maintains a hidden `FTS_DOC_ID` for a FULLTEXT
 * index and DocUp must never declare it — ADR 0004 measured that declaring it
 * makes bulk `INSERT` fail with `ERROR 182 (HY000) Invalid InnoDB FTS Doc ID`,
 * which would have broken artifact ingestion on the first real build. The
 * surrogate `id` here is an ordinary `BIGINT UNSIGNED AUTO_INCREMENT`,
 * allowlisted by name in `ArchitectureTest` and in `SchemaConformanceTest`, and
 * `uuid` is the §9.1.1 business key beside it.
 *
 * ## 🛑 Why `search_documents` carries no foreign keys
 *
 * §8.16.11: "It *can* carry foreign keys; it does not, because the retention
 * sweep must not cascade." The sweep deletes by `build_id` in batches (§10.9 —
 * the table is unpartitionable, so `DROP PARTITION` retention is impossible and
 * batched deletes plus a scheduled `OPTIMIZE TABLE` are the only option). A
 * cascade from `builds` would turn one artifact reap into an unbounded,
 * unbatched delete inside somebody else's transaction, on a §10.9 hot table.
 *
 * `search_mount_scopes` is the opposite case and does carry them: it is O(mounts)
 * rather than O(sections), and an orphan row there would describe a mount that
 * no longer exists while still naming a scope.
 */
return new class extends Migration
{
    public function up(): void
    {
        /*
         * One row per (build, section). Shared by every project that mounts the
         * build — §8.16.5's "indexed once".
         */
        Schema::create('search_documents', function (Blueprint $table): void {
            /*
             * 🛑 §9.1.3's single allowlisted AUTO_INCREMENT, and the one place
             * in DocUp where `$table->id()` is correct rather than a mistake.
             *
             * It is here because InnoDB wants a FULLTEXT table to have a
             * monotonically increasing integer key and manages `FTS_DOC_ID`
             * itself when none is declared (ADR 0004). A BINARY(16) UUIDv7
             * primary key would still work, but it would leave InnoDB
             * maintaining a second hidden integer alongside it for no gain.
             */
            $table->id();

            /*
             * §9.1.1's business key, so every other table and every API can
             * name a document without depending on an integer the retention
             * sweep and `OPTIMIZE TABLE` may renumber.
             */
            $table->binary('uuid', 16, true)->unique();
            $table->string('uuid_text', 36)->virtualAs('BIN_TO_UUID(uuid)')->nullable();

            /*
             * 🛑 §8.16.5's key. No foreign key, per the class note. Not indexed
             * on its own either: every read goes through
             * (build_id, build_generation), and a second index on the leading
             * column of a composite one earns nothing on a §10.9 hot table.
             */
            $table->binary('build_id', 16, true);

            /*
             * 🛑 §8.16.7's generation, per build. "Index consistency with
             * immutable builds MUST be maintained by a `build_generation` field
             * plus delete-by-filter."
             *
             * A build's bytes are immutable (§8.8.1), so its sections change
             * only when DocUp's own extractor changes — which is why
             * `extractor_version` is beside it. The generation is what lets a
             * re-extraction be written in full and then switched to, rather
             * than updated in place with a window in which half the sections
             * are old.
             */
            $table->unsignedBigInteger('build_generation');

            /* §8.16.8's declared filterable: the content's own language. */
            $table->char('language', 5)->default('en');

            /*
             * 🛑 §8.16.5: "a path **relative to the build**, never … an absolute
             * URL". Relative to the build's `html/` root, so `guide/index.html`
             * rather than `html/guide/index.html` and never
             * `https://docs.example.com/en/latest/guide/`. The URL is composed
             * at query time by `App\Search\SearchUrls` from the manifest's
             * mount table, which is what makes one indexed build serve correct
             * URLs for every project that mounts it.
             */
            $table->string('path', 512);
            $table->binary('path_hash', 20, true)->storedAs('UNHEX(SHA1(path))');

            /*
             * The heading's own `id`, or NULL for the page-level section that
             * precedes the first heading. §9.1.5's companion hash, over
             * `COALESCE` so the unique index below is total — a NULL anchor
             * must still collide with another NULL anchor on the same path, and
             * a nullable column in a UNIQUE index does not (§18.21's idiom,
             * the same one `theme_revisions.scope_key` uses).
             */
            $table->string('anchor', 190)->nullable();
            $table->binary('anchor_hash', 20, true)->storedAs("UNHEX(SHA1(COALESCE(anchor, '')))");

            /* §8.16.3's three boost levels, as three columns. */
            $table->string('title', 512)->default('');
            $table->string('heading_path', 1024)->default('');
            $table->string('page_title', 512)->default('');
            $table->mediumText('content');

            /*
             * 🛑 §8.16.3's "−10…+10 per-page rank honouring `search.ranking`".
             *
             * Named `page_rank` and not `rank`: `RANK` is a reserved word in
             * MySQL 8 (the window function), so every hand-written query
             * against it would need backticks and the first one that forgot
             * would fail with a syntax error naming the wrong thing.
             */
            $table->tinyInteger('page_rank')->default(0);

            /* Document order within the page, so equal scores order stably. */
            $table->unsignedInteger('position')->default(0);

            /*
             * Which of §8.16.3's and §8.16.4's routes produced this row. Kept
             * because the two disagree in a way an operator needs to see: a
             * generator's own index knows the section titles the theme renders,
             * while HTML extraction knows only what survived into the markup.
             */
            $table->enum('extracted_from', ['html', 'material', 'sphinx']);

            /*
             * The extractor that wrote it. §8.16.3's rules are DocUp's, so a
             * change to main-content detection or stripping changes every
             * document — and the only way to know which rows predate the change
             * is to have written the number down. `ChromeInjector::VERSION`
             * exists for the same reason and Phase 28 needed it in its first
             * week.
             */
            $table->unsignedSmallInteger('extractor_version');

            $table->datetime('created_at', 3)->nullable();

            /* One row per section per pass. */
            $table->unique(
                ['build_id', 'build_generation', 'path_hash', 'anchor_hash'],
                'search_documents_section_unique',
            );

            /*
             * The read and the delete-by-filter both start here: a query knows
             * the build ids it may read and the generation each is live at, and
             * the retention sweep deletes by exactly this prefix.
             */
            $table->index(['build_id', 'build_generation'], 'search_documents_generation_index');
        });

        /*
         * 🛑 The three FULLTEXT indexes §8.16.3's three boost levels need, and
         * they are three because MySQL gives no other way to weight a field.
         *
         * `MATCH(title) AGAINST (…)` is only legal with a FULLTEXT index on
         * exactly `(title)`; there is no per-field weight on a composite index
         * and no equivalent of Meilisearch's `searchableAttributes` ordering.
         * So the composite index answers *whether* a row matches and the two
         * narrow ones answer *how well it matched in the title* and *in the
         * nested heading path* — which is what
         * `MysqlFulltextEngine::relevance()` combines.
         *
         * `content` gets no index of its own because it is the baseline: its
         * contribution is already in the composite score.
         *
         * Declared in raw SQL because Laravel's `fullText()` emits a single
         * index and these are three with specific names that
         * `SchemaConformanceTest` asserts, and because the whole point of
         * ADR 0004 is that this table's FULLTEXT machinery is explicit and
         * reviewable rather than generated.
         *
         * 🛑 **Three statements, not one `ALTER TABLE` with three clauses.**
         * Measured on MySQL 8.4: the combined form fails with
         * `ERROR 1795 (HY000) InnoDB presently supports one FULLTEXT index
         * creation at a time`. It is a hard InnoDB limitation, not a syntax
         * preference, and it is invisible until a schema wants a second
         * FULLTEXT index — which no table in DocUp did before this one. Added
         * to §14.3's trap list, beside the `FTS_DOC_ID` finding it rhymes with:
         * both are InnoDB FULLTEXT behaviours that the first real use
         * discovers.
         */
        foreach ([
            '`search_documents_ft_all` (`title`, `heading_path`, `content`)',
            '`search_documents_ft_title` (`title`)',
            '`search_documents_ft_heading` (`heading_path`)',
        ] as $index) {
            DB::statement('ALTER TABLE `search_documents` ADD FULLTEXT INDEX '.$index);
        }

        /*
         * 🛑 §8.16.5's "indexed **once**", made decidable without asking an
         * engine.
         *
         * One row per (build, generation): which extractor wrote it, by which
         * route, how many sections it produced, and whether the generation is
         * finished. The indexer consults this before reading a single artifact
         * byte, which is what makes "a reused build is indexed once" a property
         * of the code rather than a hope — the second project to mount a build
         * finds a `live` row here and skips extraction entirely.
         *
         * It is also driver-independent on purpose. Asking Meilisearch "which
         * generations of this build do you hold" is possible and awkward;
         * asking it on a per-build basis during a 5,000-page pass is a network
         * round trip per build. The bookkeeping belongs beside the authorisation
         * facts, in the database, under both drivers.
         *
         * No foreign key on `build_id`, for the reason §8.16.11 gives for
         * `search_documents`: the retention sweep must not cascade.
         */
        Schema::create('search_build_index', function (Blueprint $table): void {
            $table->uuidKey();

            $table->binary('build_id', 16, true);
            $table->unsignedBigInteger('generation');

            /* Which extractor, so a later release can find its own rows. */
            $table->unsignedSmallInteger('extractor_version');
            $table->enum('extracted_from', ['html', 'material', 'sphinx']);

            /*
             * 🛑 `writing` is why this column exists. A generation is written
             * in batches (§9.2), so there is a window in which half its
             * sections exist — and a scope row pointing at it during that
             * window would serve half a build. Nothing points at a generation
             * until it is `live`, and the swap that makes it live is the same
             * statement that supersedes its predecessor.
             */
            $table->enum('state', ['writing', 'live', 'superseded'])->default('writing');

            $table->unsignedInteger('section_count')->default(0);
            $table->unsignedInteger('document_count')->default(0);

            /*
             * Pages the extractor declined — oversized, unparseable, or holding
             * no text. Recorded rather than ignored, because an operator
             * investigating "this page is not searchable" needs to know whether
             * it was skipped, and §8.16.3's caps mean the answer is sometimes
             * yes (see `SectionExtractor::MAX_DOCUMENT_BYTES`).
             */
            $table->unsignedInteger('skipped_count')->default(0);

            $table->datetime('indexed_at', 3)->nullable();
            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique(['build_id', 'generation'], 'search_build_index_generation_unique');

            /*
             * 🛑 One index, named explicitly, and no bare `index('state')`
             * beside it. Laravel derives an index's name from the table and the
             * columns, so `index(['build_id', 'state'], 'search_build_index_state_index')`
             * and `index('state')` both want to be called
             * `search_build_index_state_index` — and MySQL answers
             * `ERROR 1061 Duplicate key name`, naming an index neither line
             * mentions. The prefix answers "which generation of this build is
             * live"; the retention sweep's "every superseded generation" uses
             * it too, since `state` alone would be a scan of one value.
             */
            $table->index(['build_id', 'state'], 'search_build_index_state_index');
            $table->index(['state', 'indexed_at'], 'search_build_index_sweep_index');
        });

        /*
         * §8.16.8's declared filterable set, and §8.12.21's mandatory visibility
         * scope. One row per (project version, mount) per generation.
         */
        Schema::create('search_mount_scopes', function (Blueprint $table): void {
            $table->uuidKey();

            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_id', index: false);
            $table->uuidForeign('project_version_id');

            /*
             * The `component_mounts` row, or NULL for a version whose published
             * manifest predates the mount being recorded. Nullable because the
             * manifest is the authority on what is published and a mount row
             * can be deleted while the manifest it was published into stays
             * immutable — so a scope row may legitimately outlive its mount.
             */
            $table->uuidForeign('component_mount_id', nullable: true, index: false);

            /* Which build this mount exposes, and at which document generation. */
            $table->binary('build_id', 16, true);
            $table->unsignedBigInteger('build_generation');

            /*
             * 🛑 §10.8's `search_generation` for this project, as the value this
             * row belongs to. The atomic swap is one `UPDATE projects SET
             * search_generation = :new`; a query reads that number once and
             * matches only rows carrying it, so there is **no window in which
             * both generations answer** — the old generation's rows stop being
             * selected by the same statement that starts selecting the new
             * ones.
             */
            $table->unsignedBigInteger('generation');

            /*
             * 🛑 §8.12.21: "Every search document MUST carry a visibility scope
             * identifier as a mandatory server-side filter."
             *
             * The §12.3 lattice value that governs this mount context, already
             * narrowed by project visibility, version visibility and mount
             * exposure. It is a **cached conjunction** and not a decision: the
             * decision is still `EffectiveAccess`, asked per query. This column
             * is what lets the SQL refuse 199,000 of 200,000 sections before
             * PHP sees any of them.
             */
            $table->enum('scope', ['public', 'authenticated', 'members', 'restricted']);

            /* §8.16.6's "each matched mount's `min_access`", as published. */
            $table->enum('min_access', ['public', 'authenticated', 'members', 'restricted'])
                ->nullable();

            /* §8.16.8's declared filterable. */
            $table->char('language', 5)->default('en');

            /*
             * 🛑 §8.16.9: "By default only `default`, `stable` and `latest`
             * versions MUST be indexed." Recorded per row so an operator can
             * see *why* a version is in the index, and so a pointer moving away
             * from a version removes it at the next generation rather than
             * leaving it searchable for ever.
             */
            $table->enum('channel', ['default', 'stable', 'latest']);

            $table->datetime('created_at', 3)->nullable();

            /*
             * §18.21's sentinel again, for the same reason as `anchor_hash`: the
             * unique index must be total, and `component_mount_id` is nullable.
             */
            $table->binary('mount_key', 16, true)
                ->storedAs('COALESCE(component_mount_id, 0x00000000000000000000000000000000)');

            $table->unique(
                ['project_id', 'generation', 'project_version_id', 'build_id', 'mount_key'],
                'search_mount_scopes_unique',
            );

            /* The query's own prefix: this project, this generation, these scopes. */
            $table->index(['project_id', 'generation', 'scope'], 'search_mount_scopes_query_index');

            /* The join back to the documents, and the retention sweep's reverse lookup. */
            $table->index(['build_id', 'build_generation'], 'search_mount_scopes_build_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_id')->references('id')->on('projects')->cascadeOnDelete();
            $table->foreign('project_version_id')->references('id')->on('project_versions')->cascadeOnDelete();
        });

        Schema::table('builds', function (Blueprint $table): void {
            /*
             * 🛑 §8.16.3's `search.ranking` and `search.ignore`, recorded at
             * build time from the repository's own `.docup.yaml`.
             *
             * The same place and the same shape as `nav_json`, and for the same
             * reason `BuildPipeline::recordDeclaredNavigation()` gives: the
             * configuration is a fact about **this build**, and the indexer
             * runs long afterwards. Reading the repository at index time would
             * be wrong twice over — §8.21.6's direct uploads have no
             * repository, and a repository's branch may have moved on since the
             * build, so a page's rank would change without a rebuild.
             *
             * 🛑 Stored **raw**, exactly as the author wrote it, like
             * `nav_json`. {@see \App\Search\SearchRanking} is the one place
             * that interprets it, and it treats the value as hostile — a
             * second site that half-normalised it would be a trust boundary in
             * two places.
             */
            $table->json('search_config')->nullable()->after('nav_json');
        });

        Schema::table('projects', function (Blueprint $table): void {
            /*
             * 🛑 §10.8's `search_generation`: "bumped by reindex, keys the
             * search filter, fails closed". The live generation of
             * `search_mount_scopes` for this project.
             */
            $table->unsignedBigInteger('search_generation')->default(0)->after('policy_generation');

            /*
             * 🛑 §8.12.21's gate: "a project's search MUST be **disabled** while
             * its search generation lags its policy generation".
             *
             * This is the value of `policy_generation` that the live search
             * generation was built under, and it is a **separate** column from
             * `search_generation` deliberately. `search_generation` counts
             * reindexes and `policy_generation` counts policy writes; they are
             * different number spaces, and comparing them directly would make
             * the gate meaningless in the disclosing direction — a project that
             * republished five times would have a search generation above any
             * policy generation it could reach, so a tightened policy would
             * never close the gate.
             *
             * What can meaningfully lag a policy counter is the policy counter
             * the index was built under. That is this column, and it is what
             * `ReaderGate::authorise(searchGeneration: …)` is passed. An
             * amendment to §8.12.21's wording is proposed in the build log.
             */
            $table->unsignedBigInteger('search_policy_generation')->default(0)->after('search_generation');

            /* When the live generation finished. NULL means never indexed. */
            $table->datetime('search_indexed_at', 3)->nullable()->after('search_policy_generation');

            /*
             * 🛑 §8.16.1's threshold input: "Meilisearch … **recommended above a
             * measured section count**, with a `doctor` warning at the
             * threshold".
             *
             * Written by the indexer so `doctor` can sum a column instead of
             * running `COUNT(*)` over a §10.9 hot table — which at 200,000
             * sections is the one query an operator runs that makes search slow
             * for everybody else.
             */
            $table->unsignedInteger('search_section_count')->default(0)->after('search_indexed_at');
        });

        DataClassification::annotate('search_documents', [
            ['id', 'operational', 'not_applicable', null, '🛑 §9.1.3 / ADR 0004: the single allowlisted AUTO_INCREMENT'],
            ['uuid', 'operational', 'not_applicable', null, '§9.1.1 business key beside the surrogate'],
            ['uuid_text', 'derived', 'not_applicable', null, 'generated view of uuid'],
            ['build_id', 'operational', 'not_applicable', 'builds', '🛑 §8.16.5: keyed to the build, never to a URL'],
            ['build_generation', 'operational', 'not_applicable', null, "🛑 §8.16.7's generation, for delete-by-filter"],
            ['language', 'operational', 'not_applicable', null, "§8.16.8's declared filterable"],
            ['path', 'content', 'content', 'artifact', '🛑 §8.16.5: relative to the build'],
            ['path_hash', 'derived', 'not_applicable', null, '§9.1.5 companion hash'],
            ['anchor', 'content', 'content', 'artifact', "the heading's own id; NULL before the first heading"],
            ['anchor_hash', 'derived', 'not_applicable', null, '§18.21 sentinel; makes the unique index total'],
            ['title', 'content', 'content', 'artifact', "§8.16.3's title boost"],
            ['heading_path', 'content', 'content', 'artifact', "§8.16.3's nested title boost"],
            ['page_title', 'content', 'content', 'artifact', "the page's own title, for result context"],
            ['content', 'content', 'content', 'artifact', "the section's text, with navigation stripped"],
            ['page_rank', 'operational', 'not_applicable', null, "🛑 §8.16.3's −10…+10 from search.ranking"],
            ['position', 'derived', 'not_applicable', null, 'document order, so equal scores order stably'],
            ['extracted_from', 'operational', 'not_applicable', null, '§8.16.3 HTML or §8.16.4 structured index'],
            ['extractor_version', 'operational', 'not_applicable', null, 'which extractor wrote it'],
            ['created_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('search_build_index', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['build_id', 'operational', 'not_applicable', 'builds', '🛑 §8.16.5: the unit of "indexed once"'],
            ['generation', 'operational', 'not_applicable', null, "🛑 §8.16.7's per-build generation"],
            ['extractor_version', 'operational', 'not_applicable', null, 'which extractor wrote it'],
            ['extracted_from', 'operational', 'not_applicable', null, '§8.16.3 HTML or §8.16.4 structured index'],
            ['state', 'operational', 'not_applicable', null, '🛑 writing → live → superseded; nothing reads `writing`'],
            ['section_count', 'derived', 'not_applicable', null, "§8.16.1's threshold input"],
            ['document_count', 'derived', 'not_applicable', null, 'pages extracted'],
            ['skipped_count', 'derived', 'not_applicable', null, "pages the extractor declined, with §8.16.3's caps as the reason"],
            ['indexed_at', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('search_mount_scopes', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', 'organisations', '§8.2.1 tenant'],
            ['project_id', 'operational', 'not_applicable', 'projects', "§8.16.8's declared filterable"],
            ['project_version_id', 'operational', 'not_applicable', 'project_versions', "§8.16.8's declared filterable"],
            ['component_mount_id', 'operational', 'not_applicable', 'component_mounts', 'which mount exposes the build'],
            ['build_id', 'operational', 'not_applicable', 'builds', 'the build this mount publishes'],
            ['build_generation', 'operational', 'not_applicable', null, 'which document generation to read'],
            ['generation', 'operational', 'not_applicable', null, "🛑 §10.8's search_generation; the atomic swap"],
            ['scope', 'operational', 'not_applicable', null, '🛑 §8.12.21 mandatory server-side visibility filter'],
            ['min_access', 'operational', 'not_applicable', null, "§8.16.6's per-mount ceiling, as published"],
            ['language', 'operational', 'not_applicable', null, "§8.16.8's declared filterable"],
            ['channel', 'operational', 'not_applicable', null, '🛑 §8.16.9: default, stable and latest only'],
            ['mount_key', 'derived', 'not_applicable', null, '§18.21 sentinel; makes the unique index total'],
            ['created_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('builds', [
            ['search_config', 'content', 'content', null, "🛑 §8.16.3's search.ranking and search.ignore, as the author wrote them"],
        ]);

        DataClassification::annotate('projects', [
            ['search_generation', 'operational', 'not_applicable', null, '§10.8: reindex; keys the search filter'],
            ['search_policy_generation', 'operational', 'not_applicable', null, '🛑 §8.12.21: the policy generation the index was built under'],
            ['search_indexed_at', 'operational', 'not_applicable', null, 'when the live generation finished'],
            ['search_section_count', 'operational', 'not_applicable', null, "§8.16.1's Meilisearch threshold input"],
        ]);
    }

    public function down(): void
    {
        DataClassification::forget('builds', ['search_config']);
        DataClassification::forget('projects', [
            'search_generation',
            'search_policy_generation',
            'search_indexed_at',
            'search_section_count',
        ]);
        DataClassification::forget('search_mount_scopes');
        DataClassification::forget('search_build_index');
        DataClassification::forget('search_documents');

        Schema::table('builds', function (Blueprint $table): void {
            $table->dropColumn(['search_config']);
        });

        Schema::table('projects', function (Blueprint $table): void {
            $table->dropColumn([
                'search_generation',
                'search_policy_generation',
                'search_indexed_at',
                'search_section_count',
            ]);
        });

        Schema::dropIfExists('search_mount_scopes');
        Schema::dropIfExists('search_build_index');
        Schema::dropIfExists('search_documents');
    }
};
