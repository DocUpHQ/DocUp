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
 * Projects, the slug reservation that outlives them, and role assignments
 * (§8.2.8, §8.2.9, §8.2.10, §10.1, §12.1).
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('projects', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');

            $table->string('slug', 80);
            $table->string('name', 160);
            $table->string('description', 500)->nullable();

            /*
             * 🛑 §8.2.10. The four-value lattice of §12.3, stored and
             * authoritative at decision time — never derived, never a listing
             * flag. This is the operator's single kill switch: a project at
             * `members` serves nothing publicly however permissive a version or
             * a reader-policy rule is, which is why §12.3 evaluates it first.
             *
             * The same four values and the same order appear on
             * `project_versions.visibility`, `components.min_access` and
             * `domain_mounts.mount_exposure`, so that "permits", "stricter" and
             * "narrows" are one relation rather than three mappings.
             *
             * Defaults to the strongest level. A project that is public by
             * default is a project that leaks on the operator's first mistake.
             */
            $table->enum('visibility', ['public', 'authenticated', 'members', 'restricted'])
                ->default('restricted');

            /*
             * §8.2.9: the single audited flag that opts a project out of
             * organisation-level role inheritance, and the only escape from
             * additive inheritance. Defaults to inheriting, because the
             * surprising direction is a project nobody in the organisation can
             * administer.
             */
            $table->boolean('inherit_organisation_roles')->default(true);

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();
            $table->datetime('deleted_at', 3)->nullable()->index();

            $table->unique(['organisation_id', 'slug']);
            $table->index(['organisation_id', 'visibility']);

            $table->foreign('organisation_id')
                ->references('id')->on('organisations')
                ->cascadeOnDelete();
        });

        /*
         * 🛑 This table exists because two requirements collide.
         *
         * §8.2.8: "Project and version slugs MUST NOT be reusable after
         * deletion." §8.22.6: `deleted_at` is a recovery window, not a state,
         * with a MANDATORY hard purge at 30 days.
         *
         * Soft deletion alone satisfies neither for long: while the row
         * survives, its UNIQUE (organisation_id, slug) reserves the slug — but
         * the hard purge then deletes the row and frees the slug, silently
         * breaking §8.2.8 thirty days after any deletion. A reservation that
         * outlives the purge is the only way to hold both.
         *
         * It therefore holds NO personal data and is never purged: just the
         * organisation, the slug and when it was taken. That is also why it is
         * a separate table rather than a flag on `projects` — a row kept
         * forever must contain nothing that erasure is obliged to remove.
         *
         * Why slugs may not be recycled at all: a slug appears in published
         * documentation URLs, in external links and in readers' bookmarks.
         * Reusing one silently redirects an audience to different content under
         * a URL they already trust, which is a far worse failure than a
         * collision error at creation time.
         */
        Schema::create('project_slug_reservations', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');

            $table->string('slug', 80);

            // Which project held it. Deliberately not a foreign key: the
            // project row is hard-purged at 30 days and this reservation must
            // survive that, so a constraint would either block the purge or
            // cascade away the reservation.
            $table->binary('former_project_id', 16, true);

            $table->datetime('reserved_at', 3);

            $table->unique(['organisation_id', 'slug']);

            $table->foreign('organisation_id')
                ->references('id')->on('organisations')
                ->cascadeOnDelete();
        });

        Schema::create('role_assignments', function (Blueprint $table): void {
            $table->uuidKey();

            /*
             * Nullable because an installation-scoped assignment belongs to no
             * organisation. Every other scope carries one, and the CHECK
             * constraint below ties the two together.
             */
            $table->uuidForeign('organisation_id', nullable: true);

            // §10.1: a role is held by a user, a provider group, or a token.
            $table->enum('subject_type', ['user', 'group', 'api_token']);
            $table->uuidForeign('subject_id');

            $table->enum('scope_type', ['installation', 'organisation', 'collection', 'project']);

            // NULL for installation scope: there is exactly one installation,
            // so there is nothing to name.
            $table->uuidForeign('scope_id', nullable: true);

            // The §8.13.1 roles. An ENUM rather than a string so the database
            // rejects a value the Role enum does not know, which is the same
            // guarantee in both directions.
            $table->enum('role', [
                'installation_owner',
                'installation_security_admin',
                'installation_auditor',
                'org_admin',
                'org_member',
                'org_auditor',
                'project_admin',
                'project_maintainer',
                'project_writer',
                'project_reader',
            ]);

            /*
             * §10.1. `idp_mapping` matters operationally: §8.13.7 requires
             * IdP-sourced assignments to be reconciled — added *and removed* —
             * on every login, so the source has to be recorded or reconciliation
             * cannot tell which rows it owns and would either strip manual
             * grants or leave revoked ones in place.
             */
            $table->enum('source', ['manual', 'invite', 'idp_mapping', 'scim'])->default('manual');

            $table->datetime('expires_at', 3)->nullable()->index();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            /*
             * 🛑 A STORED generated column, not a nullable one, so the unique
             * index is total.
             *
             * MySQL permits unlimited NULLs in a UNIQUE index, so a unique key
             * over a nullable `scope_id` would silently stop constraining
             * exactly the rows where `scope_id` is NULL — every
             * installation-scoped assignment. The same person could then be
             * granted `installation_owner` any number of times.
             *
             * §18.21 lists MySQL's partial-uniqueness idioms as still
             * unverified, so this deliberately avoids depending on them:
             * COALESCE to a zero sentinel is never NULL, and the index is
             * therefore total under any of the behaviours §18.21 might turn out
             * to have.
             */
            $table->binary('scope_key', 16, true)
                ->storedAs("COALESCE(scope_id, UNHEX(REPEAT('0', 32)))");

            $table->unique(['subject_type', 'subject_id', 'scope_type', 'scope_key', 'role'], 'role_assignments_grant_unique');

            // The resolution query: every assignment for one subject, which
            // §12.1 then unions across scopes.
            $table->index(['subject_type', 'subject_id']);
            $table->index(['scope_type', 'scope_key']);

            $table->foreign('organisation_id')
                ->references('id')->on('organisations')
                ->cascadeOnDelete();
        });

        /*
         * The scope/id pairing, enforced by the database rather than trusted of
         * callers. MySQL 8.0.16+ evaluates CHECK constraints, so this is a real
         * constraint and not documentation.
         *
         * Expressed as two implications: installation scope has no scope_id,
         * and every other scope must have one. Written here rather than in the
         * Blueprint because Laravel's schema builder has no CHECK support.
         */
        DB::statement(
            'ALTER TABLE role_assignments ADD CONSTRAINT role_assignments_scope_id_pairing CHECK (
                (scope_type = \'installation\' AND scope_id IS NULL)
                OR (scope_type <> \'installation\' AND scope_id IS NOT NULL)
            )'
        );

        /*
         * 🛑 §8.22.5 — the single most important data-model consequence of the
         * erasure promise, and a Phase-00 immutable rather than a late
         * discovery.
         *
         * The audit chain hashes only opaque identifiers. Human-readable labels
         * live here, mutably, outside the chain, and erasure overwrites them
         * with a tombstone. Denormalising a name into the chained payload would
         * make "erasure removes all personal data" and "the chain still
         * verifies" mutually exclusive — you could satisfy either but never
         * both, and the choice would be discovered in Phase 35 with the whole
         * audit log already written.
         */
        Schema::create('actor_labels', function (Blueprint $table): void {
            $table->uuidKey();

            // The actor an audit event refers to. Not a foreign key to `users`
            // on purpose: an actor may be a token or a provider group, and the
            // label must outlive a hard-purged user so the audit log stays
            // readable as "a deleted account" rather than a bare identifier.
            $table->binary('actor_id', 16, true)->unique();

            $table->string('label', 255);

            // Set when erasure replaces the label with a tombstone, so the
            // difference between "never had a label" and "had one, erased" is
            // legible. §8.22.9 requires the boundary to be stated honestly, and
            // that includes in the data.
            $table->datetime('tombstoned_at', 3)->nullable();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();
        });

        DataClassification::annotate('projects', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['slug', 'operational', 'not_applicable', null, 'appears in published URLs; never reused (§8.2.8)'],
            ['name', 'operational', 'not_applicable', null, null],
            ['description', 'operational', 'not_applicable', null, 'operator-authored'],
            ['visibility', 'operational', 'not_applicable', null, '§8.2.10 kill switch; authoritative at decision time'],
            ['inherit_organisation_roles', 'operational', 'not_applicable', null, '§8.2.9 audited flag'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
            ['deleted_at', 'operational', 'not_applicable', null, '§8.22.6 recovery window; hard purge at 30 days'],
        ]);

        DataClassification::annotate('project_slug_reservations', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key'],
            ['slug', 'operational', 'not_applicable', null, 'reserved against reuse (§8.2.8)'],
            ['former_project_id', 'operational', 'not_applicable', null, 'no FK: must outlive the §8.22.6 hard purge'],
            ['reserved_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('role_assignments', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key; NULL at installation scope'],
            ['subject_type', 'operational', 'not_applicable', null, null],
            // What a person is permitted to do is personal data about them.
            ['subject_id', 'pseudonymous', 'platform', null, 'identifies a person, group or token'],
            ['scope_type', 'operational', 'not_applicable', null, null],
            ['scope_id', 'operational', 'not_applicable', null, null],
            ['scope_key', 'derived', 'not_applicable', null, 'COALESCE of scope_id; makes the unique index total'],
            ['role', 'pseudonymous', 'platform', null, "a person's permissions are data about them"],
            ['source', 'operational', 'not_applicable', null, 'drives §8.13.7 IdP reconciliation'],
            ['expires_at', 'operational', 'platform', null, null],
            ['created_at', 'operational', 'platform', null, 'reveals when access was granted'],
            ['updated_at', 'operational', 'platform', null, null],
        ]);

        DataClassification::annotate('actor_labels', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['actor_id', 'pseudonymous', 'platform', null, 'the opaque identifier the audit chain hashes (§8.22.5)'],
            // 🛑 The one column erasure overwrites rather than deletes.
            ['label', 'personal', 'platform', null, '🛑 §8.22.5: erasure overwrites this with a tombstone, keeping the chain verifiable'],
            ['tombstoned_at', 'operational', 'platform', null, 'distinguishes "never labelled" from "erased"'],
            ['created_at', 'operational', 'platform', null, null],
            ['updated_at', 'operational', 'platform', null, null],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('actor_labels');
        Schema::dropIfExists('role_assignments');
        Schema::dropIfExists('project_slug_reservations');
        Schema::dropIfExists('projects');

        foreach (['actor_labels', 'role_assignments', 'project_slug_reservations', 'projects'] as $table) {
            DataClassification::forget($table);
        }
    }
};
