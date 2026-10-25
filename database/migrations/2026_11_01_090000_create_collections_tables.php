<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * §8.2.5's collections — DocUp's answer to Read the Docs subprojects (§10.1).
 *
 * > "The system MUST support **collections**: a named grouping of projects for
 * > presentation and navigation, DocUp's equivalent of Read the Docs
 * > subprojects. A collection is a *hosting and presentation* construct; its
 * > effect on access is only the intersection rule in §8.12.8. It is never a
 * > separate authorisation primitive."
 *
 * 🛑 **Neither table carries an access column, and that is the design.**
 * §8.12.8: "`reader_policies` is keyed on `project_id` and a collection holds
 * no policy of its own (§10.1, §10.6), so a widening inheritance flag would
 * have nothing to inherit from and would exist only as a way to defeat this
 * requirement." A `collections.visibility` column would be exactly that flag —
 * the intersection is over each member project's own visibility and the
 * exposure of the mount it was given, both of which already exist. An
 * architecture test asserts the absence, because the column somebody adds "to
 * make the index easier to query" is the one that widens access.
 *
 * 🛑 **A member is served by a `domain_mounts` row, not by a second resolver
 * path.** §8.10.1 already makes "collection grouping" one of the seven hosting
 * shapes that MUST be a `domain_mounts` row keyed `(domain_id, path_prefix)`,
 * and §17.4 freezes the §7.3 grammar at the end of Phase 04. So attaching a
 * member *materialises a mount* at the collection's prefix and the resolver is
 * untouched: `collection_projects.domain_mount_id` is the link between the
 * presentation construct and the hosting row it produced.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('collections', function (Blueprint $table): void {
            $table->uuidKey();

            // §8.2.1's tenancy key, on every tenant-reachable row.
            $table->uuidForeign('organisation_id');

            /*
             * 🛑 The project at the collection's root, and the reason a
             * collection has one at all: §8.21.2's `/projects/<alias>/`
             * convention is *relative to a parent*, because that is what a
             * Read the Docs subproject URL is. Without a parent, "the
             * collection's prefix" would have no domain to hang under and
             * every member would need its own mount configured by hand —
             * which is the arrangement collections exist to replace.
             *
             * Nullable so a collection can be created before its parent is
             * chosen, and `nullOnDelete` rather than `cascadeOnDelete`:
             * deleting the parent project must not silently delete the
             * grouping two other projects are still presented through.
             */
            $table->uuidForeign('parent_project_id', nullable: true);

            /*
             * The collection's own URL segment, used when the operator mounts
             * it somewhere other than under the parent's root. Held to the
             * same refusals as a member alias ({@see App\Collections\CollectionAlias}),
             * because it occupies the same kind of position.
             */
            $table->string('slug', 64);

            $table->string('name', 255);

            /*
             * §8.2.6's "supported prefix convention". Two values, and the
             * literal `/projects/<alias>/` is the default because §8.21.2
             * requires imported Read the Docs URLs to keep resolving — a
             * default of `alias` would make every imported subproject URL a
             * generated redirect instead of a live mount.
             */
            $table->enum('prefix_convention', ['projects', 'alias'])->default('projects');

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            // One collection slug per organisation: the slug is a URL segment
            // and two collections answering to it would make the prefix
            // ambiguous at the one place an operator types it.
            $table->unique(['organisation_id', 'slug'], 'collections_org_slug_unique');

            // No index on `parent_project_id` here: `uuidForeign` already made
            // one, and a second declaration is a duplicate-key error rather
            // than a no-op.

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('parent_project_id')->references('id')->on('projects')->nullOnDelete();
        });

        Schema::create('collection_projects', function (Blueprint $table): void {
            $table->uuidKey();

            $table->uuidForeign('organisation_id');
            $table->uuidForeign('collection_id');
            $table->uuidForeign('project_id');

            /*
             * §8.21.2's subproject alias — the segment a Read the Docs URL
             * carries, preserved on import so `/projects/<alias>/` keeps
             * resolving. Distinct from `projects.slug` on purpose: the same
             * project is a member of two collections under two aliases, which
             * is the whole reason the alias lives on the edge rather than on
             * the project.
             */
            $table->string('alias', 64);

            /*
             * 🛑 §4.2 puts nested collections out of scope, so a member is a
             * project and never another collection. Expressed by this column
             * being a `projects` foreign key and by there being no
             * `parent_collection_id` anywhere — a shape rather than a check,
             * because a check is what somebody relaxes.
             */

            /*
             * The `domain_mounts` row this membership produced, or null for a
             * member that is listed in the collection and not mounted under
             * it. `nullOnDelete`, so an operator deleting a mount by hand
             * leaves the membership visible and unmounted rather than deleting
             * the grouping underneath them.
             */
            $table->uuidForeign('domain_mount_id', nullable: true);

            // Presentation order in the index and the flyout. Resolution is by
            // longest prefix and never by this.
            $table->unsignedInteger('position')->default(0);

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            /*
             * One membership per project per collection. Without it a project
             * could be attached twice under two aliases and the index would
             * list it twice — and §8.21.2's generated redirects would have two
             * targets for one project.
             */
            $table->unique(['collection_id', 'project_id'], 'collection_projects_member_unique');

            /*
             * 🛑 And one alias per collection, which is the index that
             * actually holds §8.2.6's URL promise. The alias is a path
             * segment: two members sharing one would make a mounted prefix
             * ambiguous, and `domain_mounts_domain_prefix_unique` would then
             * refuse the second mount with an error naming a table the
             * operator never touched.
             */
            $table->unique(['collection_id', 'alias'], 'collection_projects_alias_unique');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('collection_id')->references('id')->on('collections')->cascadeOnDelete();
            $table->foreign('project_id')->references('id')->on('projects')->cascadeOnDelete();
            $table->foreign('domain_mount_id')->references('id')->on('domain_mounts')->nullOnDelete();
        });

        DataClassification::annotate('collections', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['parent_project_id', 'operational', 'not_applicable', null, '§8.21.2 the project the prefix hangs under'],
            ['slug', 'operational', 'not_applicable', null, '§8.2.6 URL segment'],
            ['name', 'operational', 'not_applicable', null, 'presentation only'],
            ['prefix_convention', 'operational', 'not_applicable', null, "§8.2.6; 'projects' preserves imported RTD URLs"],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('collection_projects', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['collection_id', 'operational', 'not_applicable', null, null],
            ['project_id', 'operational', 'not_applicable', null, '🛑 §4.2 a member is a project, never a collection'],
            ['alias', 'operational', 'not_applicable', null, '§8.21.2 the subproject URL segment'],
            ['domain_mount_id', 'operational', 'not_applicable', null, '§8.10.1 the hosting row this membership produced'],
            ['position', 'operational', 'not_applicable', null, 'presentation order only'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('collection_projects');
        Schema::dropIfExists('collections');

        DataClassification::forget('collection_projects');
        DataClassification::forget('collections');
    }
};
