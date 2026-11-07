<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * §8.11.2's redirect rules, §8.11.5's 404 chain and §8.11.6's generated
 * artefacts (§10.5).
 *
 * 🛑 Three separate things in one migration because they are one feature:
 * a URL that survives reorganisation. A rule says where a path went, the
 * chain says what happens when no rule matched, and the generated artefacts
 * are what tells a crawler which of the resulting URLs is the real one.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('redirect_rules', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_id');

            /*
             * 🛑 §8.11.2: "explicit ordering". Not insertion order and not
             * a specificity heuristic — the operator says which rule wins,
             * because the two orders disagree exactly where it matters.
             * `/api/:splat` and `/api/v1/:splat` are both prefix rules and
             * neither is "more specific" in a way a machine should guess at.
             *
             * UNIQUE so two rules cannot share a position: a tie broken by
             * insertion order is an ordering nobody chose and which changes
             * when a rule is edited.
             */
            $table->unsignedSmallInteger('position');

            /*
             * §8.11.2's six types. Read the Docs has five of these and no
             * `regex` worth the name; the sixth is why §8.11.4 exists.
             */
            $table->enum('kind', [
                'exact',
                'prefix',
                'version_agnostic',
                'clean_url',
                'html_extension',
                'regex',
            ]);

            /*
             * 🛑 §8.11.1 splits user rules into two passes around the
             * **existence probe**, and this column is which pass a rule is
             * in. A forced rule wins over a file that exists; an unforced
             * one only fires once the path has been shown to name nothing.
             *
             * The distinction is not a convenience. A forced rule is how an
             * operator retires a page that is still in the build output; an
             * unforced one is how they catch inbound links to pages that
             * were removed. Collapsing them would make the first impossible
             * and the second dangerous — every unforced rule would shadow a
             * live page the moment its pattern widened.
             */
            $table->boolean('forced')->default(false);

            /*
             * The pattern. 512 rather than 255 because a `:splat` prefix
             * over a deep component mount is long, and §8.11.4's 255 cap is
             * on **regex** patterns specifically — enforced in the
             * application, where the reason can be stated, rather than by a
             * column width that would also truncate an exact path.
             */
            $table->string('from_pattern', 512);

            /*
             * 🛑 §8.11.2: "Targets MUST be root-relative same-origin paths
             * … an absolute `http(s)://` target MUST be either refused at
             * save time or permitted only to a hostname the same
             * organisation has verified, so a redirect rule cannot become
             * an open redirect or a traffic-exfiltration primitive."
             *
             * DocUp takes the second, stricter-in-practice reading, because
             * Phase 18 already built the predicate: a proven claim is
             * `domains.claimed_host IS NOT NULL` for a domain this
             * organisation owns. 1024 because an absolute target carries a
             * scheme and a host as well as a path.
             */
            $table->string('to_target', 1024);

            /*
             * §8.11.2: "status codes 301, 302, 307 and 308. (Read the Docs
             * supports only 301/302.)" The pair that matters is 307/308:
             * they preserve the method and the body, which 301/302 are
             * permitted to drop — so a documentation API that moved needs
             * one of them and Read the Docs cannot express it.
             */
            $table->unsignedSmallInteger('status')->default(301);

            /*
             * Disabled rather than deleted, because the common operation is
             * "turn this off and see whether anything breaks" and a deleted
             * rule takes its position with it.
             */
            $table->boolean('enabled')->default(true);

            $table->string('description', 255)->nullable();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique(['project_id', 'position'], 'redirect_rules_position_unique');

            /*
             * 🛑 The index the exit criterion rests on: "a 1,000-redirect
             * project resolves in **one query** under 10 ms". Every rule for
             * a project, in position order, from one covering index — the
             * engine then matches in PHP, which is where §8.11.4's
             * deterministic evaluation cap can be counted.
             */
            $table->index(['project_id', 'enabled', 'position'], 'redirect_rules_evaluation_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_id')->references('id')->on('projects')->cascadeOnDelete();
        });

        Schema::table('domain_mounts', function (Blueprint $table): void {
            /*
             * 🛑 §8.11.6: the generated artefacts live at
             * `generated/<domain_mount_uuid>/<revision>/…`, "**separate**
             * from the immutable build artifact tree, so §8.8.1's
             * write-once rule and §8.8.2's ingest validation are untouched
             * and a rebrand or a new domain regenerates them without
             * touching a build".
             *
             * The revision is a counter on the mount rather than a build or
             * manifest id, and that is the requirement's own logic: a
             * rebrand changes `robots.txt` and touches no build, and a new
             * domain produces a whole new set for a build that has not
             * changed. Keying on anything from the build tree would make
             * those two cases impossible to express.
             */
            $table->unsignedInteger('generated_revision')->default(0)->after('position');
            $table->datetime('generated_at', 3)->nullable()->after('generated_revision');
        });

        Schema::table('build_outputs', function (Blueprint $table): void {
            /*
             * 🛑 §8.11.5, and ADR 0003's measurement: "a generator-supplied
             * `404.html` is **inherently root-anchored** — a 404 page is
             * served from arbitrary URL depth, so it cannot use relative
             * asset paths, and MkDocs Material's measured output puts all 8
             * of its root-absolute references in that one file."
             *
             * So the chain must **skip** a flagged `404.html` whenever the
             * project is served at a non-root `path_prefix` or under a
             * component mount, falling through to the branded built-in
             * rather than serving a stylesheet-less page.
             *
             * Recorded here rather than in the file manifest on purpose:
             * the file manifest's bytes are hashed into `source_digest` and
             * compared for §8.8.5's "rollback restores build 1's bytes
             * exactly", and §17.4 freezes `ArtifactIngestor`. A column is a
             * fact about the output, not a change to what an output is.
             *
             * Nullable, because every build that predates this phase has no
             * answer and "unknown" must not read as "safe" — the chain
             * treats null the same as true, which is the fail-safe
             * direction: fall through to the built-in page.
             */
            $table->boolean('not_found_root_absolute')->nullable()->after('content_sha256');
        });

        DataClassification::annotate('redirect_rules', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['project_id', 'operational', 'not_applicable', null, null],
            ['position', 'operational', 'not_applicable', null, '🛑 §8.11.2 explicit ordering, never a heuristic'],
            ['kind', 'operational', 'not_applicable', null, '§8.11.2 six rule types'],
            ['forced', 'operational', 'not_applicable', null, '🛑 §8.11.1: before or after the existence probe'],
            ['from_pattern', 'content', 'content', null, 'an author-supplied URL pattern'],
            ['to_target', 'content', 'content', null, '🛑 §8.11.2 refused unless same-origin or a proven host'],
            ['status', 'operational', 'not_applicable', null, '301, 302, 307 or 308'],
            ['enabled', 'operational', 'not_applicable', null, null],
            ['description', 'content', 'content', null, "the operator's own note"],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('domain_mounts', [
            ['generated_revision', 'operational', 'not_applicable', null, '§8.11.6 generated-artefact revision'],
            ['generated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('build_outputs', [
            ['not_found_root_absolute', 'derived', 'not_applicable', null, '🛑 §8.11.5 / ADR 0003: skip this 404.html under a prefix'],
        ]);
    }

    public function down(): void
    {
        DataClassification::forget('build_outputs', ['not_found_root_absolute']);
        DataClassification::forget('domain_mounts', ['generated_revision', 'generated_at']);
        DataClassification::forget('redirect_rules');

        Schema::table('build_outputs', function (Blueprint $table): void {
            $table->dropColumn('not_found_root_absolute');
        });

        Schema::table('domain_mounts', function (Blueprint $table): void {
            $table->dropColumn(['generated_revision', 'generated_at']);
        });

        Schema::dropIfExists('redirect_rules');
    }
};
