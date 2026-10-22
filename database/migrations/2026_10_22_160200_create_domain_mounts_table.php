<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Where a project is served on a hostname (§8.10.1, §10.5).
 *
 * 🛑 §8.10.1: "Every hosting shape — default project subdomain, custom domain,
 * apex domain, additional serving domain, path-prefix portal, collection
 * grouping and preview host — MUST be a `domain_mounts` row keyed
 * `(domain_id, path_prefix)`." One table, seven shapes. The alternative DocUp
 * rejects is a column per shape, which is how the seventh shape becomes a
 * schema change.
 *
 * This is §7.3's **first** step, which is why §17 insists the table exists in
 * Phase 04 with its full column set: the resolver is frozen at the end of this
 * phase and it matches on `path_prefix` longest-first.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('domain_mounts', function (Blueprint $table): void {
            $table->uuidKey();

            // §8.2.1 tenancy, carried even though it is derivable through the
            // domain: a global scope that must join to find the tenant is one
            // the first hand-written query bypasses.
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('domain_id');
            $table->uuidForeign('project_id');

            /*
             * '' for a mount at the host root, which is the common case.
             * Matched longest-first **on a segment boundary** (§7.3), so a mount
             * at `api` must not match a request for `apiary/...`.
             *
             * 255 characters is 1,020 bytes under utf8mb4, and combined with
             * the 16-byte domain key the unique index below is 1,036 bytes —
             * inside InnoDB's 3,072-byte limit, so this needs no companion hash
             * the way `component_mounts.mount_path` did (§9.1.5). That one is
             * combined with a version key in an index that approached the
             * limit; this one is not.
             */
            $table->string('path_prefix', 255)->default('');

            /*
             * 🛑 §8.10.2: "For every subsequent verified domain, `mode` MUST
             * default to **`serve`**: every verified domain answers 200, with an
             * automatic `rel=canonical` to the project's canonical mount. Read
             * the Docs' canonical-plus-301 behaviour is rejected as the default
             * because it makes mandatory requirement G6 decorative."
             *
             * So the default here is `serve` and the application sets
             * `canonical` explicitly on a project's first mount (§8.10.2 again:
             * "The **first** domain mount created for a project … MUST be
             * created with `mode='canonical'`").
             */
            $table->enum('mode', ['canonical', 'serve', 'redirect'])->default('serve');

            /*
             * 🛑 §8.10.3: "Exactly one canonical mount per project MUST be
             * enforced in the database by a nullable `canonical_for_project_id`
             * under a unique index."
             *
             * Generated rather than written, which is a deliberate improvement
             * on the letter of §10.4's column list: derived from `mode` it
             * cannot disagree with it. A hand-maintained column could hold a
             * project id while `mode` said `serve` — a row claiming to be
             * canonical and serving as an alias, or the reverse — and nothing
             * would notice, because each column alone would look consistent.
             *
             * The idiom is §18.21's, verified on MySQL 8.4.11 in Phase 03:
             * unlimited NULLs, second non-NULL rejected with error 1062.
             *
             * 🛑 **VIRTUAL, not STORED**, and that is forced rather than
             * chosen. MySQL refuses a foreign key with `ON DELETE CASCADE` on
             * the **base column** of a *stored* generated column — error 1215,
             * "Cannot add foreign key constraint" — and `project_id` is both
             * this column's base and a cascading foreign key. Measured on
             * 8.4.11 (P04, see §18.21): with VIRTUAL the cascade is accepted
             * and all three partial-uniqueness properties still hold, so the
             * constraint is unchanged and the cascade survives. The alternative
             * was `ON DELETE RESTRICT` plus application-side cleanup, which
             * would make deleting a project fail on a row the operator cannot
             * see.
             */
            $table->binary('canonical_for_project_id', 16, true)
                ->nullable()
                ->virtualAs("IF(`mode` = 'canonical', `project_id`, NULL)");

            /*
             * §10.5. Null means "use the project's own scheme"; a value
             * overrides it for this mount, which is what lets one project serve
             * `/{version}/` on its own domain and `/{lang}/{version}/` on
             * another.
             */
            $table->enum('versioning_scheme_override', ['lang_and_version', 'multi_version', 'single_version'])
                ->nullable();

            /*
             * §10.5's `version_scope`: which versions this mount exposes. JSON
             * because it is an allowlist read whole, never filtered on in SQL —
             * and unlike the manifest's mounts (§18.8) it is not on the byte
             * path, so no benchmark gates it.
             *
             * Null means every version the project has.
             */
            $table->json('version_scope')->nullable();

            /*
             * 🛑 §10.5: "the §12.3 lattice plus 'inherit'; **narrowing only**".
             * A mount may demand more protection than the project, never less.
             * The narrowing check is §12.3's and arrives in Phase 21 with
             * `EffectiveAccess`; the column exists now because §17 puts the
             * lattice columns "on tables created in P03 and P04 rather than
             * being added here", so that mount-level privacy works from the
             * start rather than being retrofitted onto a live serving path.
             */
            $table->enum('mount_exposure', ['inherit', 'public', 'authenticated', 'members', 'restricted'])
                ->default('inherit');

            // Phase 21's and Phase 16's respectively. No foreign key: the
            // tables do not exist yet, and a column is cheaper to constrain
            // later than a frozen resolver is to change.
            $table->uuidForeign('auth_profile_id', nullable: true, index: false);
            $table->uuidForeign('theme_assignment_id', nullable: true, index: false);

            /*
             * 🛑 §8.10.2: "`is_indexable` MUST be **derived** (`mode='canonical'`),
             * not an independent default, so the canonical domain is never
             * silently `noindex`ed."
             *
             * Generated, so "derived" is structural rather than a convention
             * somebody maintains. The failure this prevents is specific and
             * quiet: a canonical mount with `is_indexable = false` serves
             * `X-Robots-Tag: noindex` on the one hostname that should be
             * indexed, and nothing is wrong with the page.
             */
            $table->boolean('is_indexable')->storedAs("`mode` = 'canonical'");

            // §10.5. Ordering among sibling mounts on one domain, for
            // presentation; resolution is by longest prefix, not by position.
            $table->unsignedInteger('position')->default(0);

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            // §10.5's stated key.
            $table->unique(['domain_id', 'path_prefix'], 'domain_mounts_domain_prefix_unique');

            // §8.10.3's one-canonical-mount-per-project constraint.
            $table->unique('canonical_for_project_id', 'domain_mounts_canonical_unique');

            $table->index(['project_id', 'mode']);

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('domain_id')->references('id')->on('domains')->cascadeOnDelete();
            $table->foreign('project_id')->references('id')->on('projects')->cascadeOnDelete();
        });

        DataClassification::annotate('domain_mounts', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['domain_id', 'operational', 'not_applicable', null, null],
            ['project_id', 'operational', 'not_applicable', null, null],
            ['path_prefix', 'operational', 'not_applicable', null, "§7.3's first grammar step"],
            ['mode', 'operational', 'not_applicable', null, '§8.10.2; serve is the default'],
            ['canonical_for_project_id', 'derived', 'not_applicable', null, '🛑 §8.10.3 one canonical mount, in the database; VIRTUAL so project_id may cascade'],
            ['versioning_scheme_override', 'operational', 'not_applicable', null, '§10.5'],
            ['version_scope', 'operational', 'not_applicable', null, '§10.5 version allowlist'],
            ['mount_exposure', 'operational', 'not_applicable', null, '🛑 §12.3 lattice plus inherit; narrowing only'],
            ['auth_profile_id', 'operational', 'not_applicable', null, 'Phase 21'],
            ['theme_assignment_id', 'operational', 'not_applicable', null, 'Phase 16'],
            ['is_indexable', 'derived', 'not_applicable', null, '🛑 §8.10.2 derived from mode, never independent'],
            ['position', 'operational', 'not_applicable', null, 'presentation order only'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('domain_mounts');
        DataClassification::forget('domain_mounts');
    }
};
