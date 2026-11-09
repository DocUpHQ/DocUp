<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Branding\TokenRegistry;
use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * §10.7's four branding tables: `token_definitions`, `theme_revisions`,
 * `theme_assets` and `theme_assignments`.
 *
 * ## 🛑 Why `token_definitions` is a table when the registry is code
 *
 * {@see TokenRegistry} is the authority — it is what validates,
 * and a row here never overrides it. The table exists for three jobs code
 * cannot do:
 *
 * 1. §8.14.1 makes the registry "plugin-extendable", so the set an installation
 *    holds depends on which plugins are installed. The table is how
 *    `docup:doctor`, an SQL query and the API answer "what does *this*
 *    installation define" without booting every plugin.
 * 2. A stored theme may name a token a later release removed. With the
 *    definitions recorded per registry version, that is a finding; without
 *    them it is a mystery.
 * 3. The dashboard joins token metadata onto a theme editor without 45 round
 *    trips through PHP.
 *
 * It is synced by `docup:branding-sync`, which the installer runs, and
 * `BrandingRegistryTest` asserts the sync is lossless both ways.
 *
 * ## 🛑 Why a mount points at an *assignment* and not at a revision
 *
 * §10.5 puts `theme_assignment_id` on `domain_mounts` and this migration is
 * where it gains its foreign key. The indirection earns its place: an
 * assignment is a **named, reusable** binding, so a reseller's twelve
 * white-labelled mounts share one assignment, and publishing a new revision of
 * that theme moves all twelve without touching a single mount row. A mount
 * pointing straight at a revision would make every publish an update of every
 * mount that used it — twelve writes to the routing table, which bumps
 * `routing_epoch` and invalidates resolution for a change that altered no
 * routing.
 */
return new class extends Migration
{
    public function up(): void
    {
        /*
         * §8.14.1's registry, materialised. Installation-wide and owned by no
         * tenant, which is why there is no `organisation_id` — a token
         * definition is a fact about the software, not about a customer.
         */
        Schema::create('token_definitions', function (Blueprint $table): void {
            $table->uuidKey();

            /* The dotted registry key. Unique, because it is the key. */
            $table->string('name', 120)->unique();

            /*
             * The type name, as a **string** and not an enum, for the reason
             * `auth_provider_bindings.type` is a string: §8.14.1's
             * "plugin-extendable" would otherwise mean a migration per plugin
             * that introduces a type. What constrains it is
             * {@see \App\Branding\TokenType}.
             */
            $table->string('type', 32);

            /* The documentation table's section heading. */
            $table->string('token_group', 60);

            /* The installation default, in the token's own grammar. */
            $table->string('default_value', 255);

            /*
             * 🛑 The dark-scheme value, and NULL means "one value in both
             * schemes" rather than "black". §8.14.7 asks for "explicit pairs or
             * a stated derivation rule" and the registry chose explicit pairs;
             * a nullable column is how a token says it is not paired.
             */
            $table->string('dark_value', 255)->nullable();

            /* §8.14.1's cascade bound: the deepest scope that may set it. */
            $table->enum('deepest_level', ['installation', 'organisation', 'project', 'mount', 'version']);

            /** The option list for an enumerated token; `[]` otherwise. */
            $table->json('options');

            /* The clamp for a length, ratio or count; both zero when unused. */
            $table->decimal('minimum', 10, 4)->default(0);
            $table->decimal('maximum', 10, 4)->default(0);

            /* The character cap for a text token; zero otherwise. */
            $table->unsignedSmallInteger('max_length')->default(0);

            /* Which `theme_assets.kind` an asset token must name. */
            $table->string('asset_kind', 32)->nullable();

            /* One line, for the operator documentation and the dashboard. */
            $table->string('purpose', 500);

            /*
             * 🛑 Whether the core registry or a plugin defines it. The sync
             * command deletes a stale `core` row and leaves `plugin` rows
             * alone, so uninstalling a plugin does not silently drop a
             * definition a theme still references — that becomes a `doctor`
             * finding instead, which is the whole reason job (2) above exists.
             */
            $table->enum('source', ['core', 'plugin'])->default('core');

            $table->timestamps();
        });

        Schema::create('theme_revisions', function (Blueprint $table): void {
            $table->uuidKey();

            /*
             * 🛑 Nullable, because an installation-scoped revision belongs to
             * no organisation — the same shape `auth_provider_bindings` has and
             * the same reason: §12.1's installation scope is above tenancy.
             */
            $table->uuidForeign('organisation_id', nullable: true);

            /*
             * The cascade rung this revision sits on. `version` is included and
             * is narrow by registry data rather than by schema: §8.14.1 limits
             * a version to the colour-scheme default and a banner, and
             * {@see \App\Branding\BrandingToken::$deepest} is what enforces it.
             * A CHECK here would have put the same rule in a second place.
             */
            $table->enum('scope_type', ['installation', 'organisation', 'project', 'mount', 'version']);
            $table->uuidForeign('scope_id', nullable: true, index: false);

            /*
             * 🛑 §18.21's verified COALESCE idiom, for the reason
             * `auth_provider_bindings.scope_key` uses it: MySQL permits
             * unlimited NULLs in a unique index, so `UNIQUE (scope_type,
             * scope_id, revision_number)` would let an installation hold any
             * number of revision 1s.
             */
            $table->binary('scope_key', 16, true)
                ->storedAs("COALESCE(scope_id, UNHEX(REPEAT('0', 32)))");

            /* Monotonic per scope, so an operator can name a revision. */
            $table->unsignedInteger('revision_number');

            /*
             * 🛑 §8.14.6: "Theme revisions MUST support **draft and preview
             * before publish**. A token edit currently going live across every
             * consuming project instantly is a foot-gun; staging is the
             * mitigation."
             *
             * Three states and not two. `superseded` rather than deleting the
             * previous publication, because a revision is what a stylesheet URL
             * is addressed by and a reader holding a year-long cache entry is
             * still entitled to the bytes behind it.
             */
            $table->enum('state', ['draft', 'published', 'superseded'])->default('draft');

            /*
             * 🛑 At most one `published` revision per scope, by §18.21's second
             * verified idiom: a UNIQUE index over a STORED generated column
             * that is NULL for every other state. Two published revisions at
             * one scope would make the cascade's answer depend on row order.
             */
            $table->binary('published_scope_key', 16, true)
                ->storedAs("IF(state = 'published', COALESCE(scope_id, UNHEX(REPEAT('0', 32))), NULL)")
                ->nullable();

            /** This level's own token values only — never the resolved set. */
            $table->json('tokens');

            /** §8.14.1's per-path locks declared at this level. */
            $table->json('locks');

            /** §8.14.3's structured chrome content. Never HTML. */
            $table->json('chrome');

            /** §8.14.13's email slot overrides. */
            $table->json('email');

            /*
             * §8.14.4's content address, over the **resolved** theme as
             * re-serialised. Nullable while a draft has never been resolved.
             */
            $table->char('content_hash', 64)->nullable()->index();

            /** §8.14.5's full report, both schemes, every pair. */
            $table->json('contrast')->nullable();
            $table->enum('contrast_verdict', ['pass', 'warn', 'refuse'])->nullable();

            /*
             * 🛑 §8.14.5's "operator override audited". The flag records that a
             * sub-3:1 theme was published deliberately; the audit event records
             * who and why. Both, because the flag is what the dashboard shows
             * on the theme for as long as it is live and an audit row is not
             * something anybody reads by accident.
             */
            $table->boolean('contrast_override')->default(false);
            $table->string('contrast_override_reason', 500)->nullable();

            $table->timestamp('published_at', 3)->nullable();
            $table->uuidForeign('published_by', nullable: true);
            $table->uuidForeign('created_by', nullable: true);
            $table->timestamps(3);

            $table->unique(['scope_type', 'scope_key', 'revision_number'], 'theme_revisions_scope_revision_unique');
            $table->unique(['scope_type', 'published_scope_key'], 'theme_revisions_one_published_per_scope');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
        });

        Schema::create('theme_assets', function (Blueprint $table): void {
            $table->uuidKey();

            $table->uuidForeign('organisation_id', nullable: true);

            /*
             * Which scope may reference it. An asset uploaded at organisation
             * scope is referenceable by that organisation's projects and
             * mounts; an installation asset by everybody. §8.2.2's
             * 404-never-403 rule is applied in {@see \App\Branding\ThemeAssets},
             * which returns null for both "no such asset" and "not yours".
             */
            $table->enum('scope_type', ['installation', 'organisation', 'project']);
            $table->uuidForeign('scope_id', nullable: true, index: false);
            $table->binary('scope_key', 16, true)
                ->storedAs("COALESCE(scope_id, UNHEX(REPEAT('0', 32)))");

            /*
             * 🛑 A closed kind list, unlike `type` on the two tables above. A
             * plugin may add a *token*; it may not add an asset kind, because
             * each kind is a distinct re-encoding path in
             * {@see \App\Branding\Assets\AssetIntake} — a GD pipeline for the
             * three raster kinds, a DOM sanitiser for SVG, a signature check
             * for WOFF2. A kind nothing could process would be an upload that
             * stored unvalidated bytes.
             */
            $table->enum('kind', ['logo', 'favicon', 'social_card', 'font']);

            /*
             * 🛑 §8.14.11: "content-addressed with the uploaded filename
             * discarded". The hash is over the bytes DocUp **wrote**, not the
             * bytes it received: re-encoding is what strips the metadata and
             * defeats the polyglot, so addressing the input would let two
             * different uploads that re-encode identically occupy two rows and
             * two URLs.
             */
            $table->char('content_hash', 64);

            /** The media type DocUp emits — always one it produced itself. */
            $table->string('media_type', 80);
            $table->unsignedInteger('byte_size');

            /** Pixel dimensions after re-encoding; NULL for a font. */
            $table->unsignedSmallInteger('width')->nullable();
            $table->unsignedSmallInteger('height')->nullable();

            /*
             * What was sniffed from the upload, which may differ from
             * `media_type` — a JPEG logo is re-encoded to PNG. Kept because an
             * operator asking "why is my logo bigger now" deserves an answer,
             * and because §8.14.11's polyglot defence is only reviewable if the
             * input type is recorded.
             */
            $table->string('source_media_type', 80);

            /*
             * 🛑 The operator's own label. The uploaded filename is discarded
             * (§8.14.11), so without this an operator picking between three
             * logos is picking between three content hashes.
             */
            $table->string('label', 160);

            $table->uuidForeign('created_by', nullable: true);
            $table->timestamps(3);

            /* One row per distinct result per scope. */
            $table->unique(['scope_type', 'scope_key', 'content_hash'], 'theme_assets_scope_hash_unique');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
        });

        Schema::create('theme_assignments', function (Blueprint $table): void {
            $table->uuidKey();

            $table->uuidForeign('organisation_id', nullable: true);

            /*
             * 🛑 The owner, as a scope rather than as `organisation_id` alone —
             * and the reason is a MySQL restriction worth recording, because
             * the obvious schema does not build.
             *
             * MySQL refuses a foreign key with a CASCADE, SET NULL or SET
             * DEFAULT referential action on the **base column of a stored
             * generated column**. So `owner_key STORED AS COALESCE(
             * organisation_id, …)` beside `organisation_id … ON DELETE CASCADE`
             * fails with error 1215, and 1215 says only "Cannot add foreign key
             * constraint".
             *
             * The remedy is the shape `auth_provider_bindings` already uses:
             * `organisation_id` is the tenancy key and carries the cascade,
             * while `scope_id` is the dimension §18.21's sentinel is derived
             * from and carries no foreign key of its own. Two columns holding
             * the same value at organisation scope, which looks redundant and
             * is what lets a tenant delete cascade through a table whose
             * uniqueness is total.
             */
            $table->enum('scope_type', ['installation', 'organisation']);
            $table->uuidForeign('scope_id', nullable: true, index: false);
            $table->binary('scope_key', 16, true)
                ->storedAs("COALESCE(scope_id, UNHEX(REPEAT('0', 32)))");

            /** The operator's name for it: "ACME white label". */
            $table->string('name', 120);

            $table->uuidForeign('theme_revision_id');

            $table->uuidForeign('created_by', nullable: true);
            $table->timestamps(3);

            $table->unique(['scope_type', 'scope_key', 'name'], 'theme_assignments_owner_name_unique');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();

            /*
             * 🛑 RESTRICT, not cascade. Deleting the revision an assignment
             * points at would silently drop every mount's theme back to the
             * project default — a visual change across a reseller's whole
             * estate caused by tidying up a revision list.
             */
            $table->foreign('theme_revision_id')->references('id')->on('theme_revisions')->restrictOnDelete();
        });

        /*
         * 🛑 §10.5's `domain_mounts.theme_assignment_id` gains its foreign key
         * here. The column has existed since Phase 04 with a comment naming
         * the wrong phase; the build log records that. `nullOnDelete` because a
         * mount with no assignment is the normal case — it inherits the
         * project's theme — so losing an assignment correctly degrades to
         * inheritance rather than blocking the delete.
         */
        Schema::table('domain_mounts', function (Blueprint $table): void {
            $table->foreign('theme_assignment_id')
                ->references('id')
                ->on('theme_assignments')
                ->nullOnDelete();
        });

        DataClassification::annotate('token_definitions', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['name', 'operational', 'not_applicable', null, '🛑 §8.14.1: the closed registry key'],
            ['type', 'operational', 'not_applicable', null, 'a string, so a plugin type needs no migration'],
            ['token_group', 'operational', 'not_applicable', null, "the documentation table's section"],
            ['default_value', 'operational', 'not_applicable', null, "the installation default, in the token's grammar"],
            ['dark_value', 'operational', 'not_applicable', null, '🛑 NULL means one value in both schemes (§8.14.7)'],
            ['deepest_level', 'operational', 'not_applicable', null, "🛑 §8.14.1's cascade bound"],
            ['options', 'operational', 'not_applicable', null, 'the option list for an enumerated token'],
            ['minimum', 'operational', 'not_applicable', null, "§8.14.2's clamp"],
            ['maximum', 'operational', 'not_applicable', null, "§8.14.2's clamp"],
            ['max_length', 'operational', 'not_applicable', null, 'character cap for a text token'],
            ['asset_kind', 'operational', 'not_applicable', null, 'which theme_assets.kind an asset token names'],
            ['purpose', 'operational', 'not_applicable', null, 'one line for the operator documentation'],
            ['source', 'operational', 'not_applicable', null, 'core or plugin; the sync command only prunes core'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('theme_revisions', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'NULL at installation scope (§12.1)'],
            ['scope_type', 'operational', 'not_applicable', null, "🛑 §8.14.1's cascade rung"],
            ['scope_id', 'operational', 'not_applicable', null, 'NULL at installation scope'],
            ['scope_key', 'derived', 'not_applicable', null, '🛑 §18.21 COALESCE sentinel; makes the unique index total'],
            ['revision_number', 'operational', 'not_applicable', null, 'monotonic per scope'],
            ['state', 'operational', 'not_applicable', null, '🛑 §8.14.6 draft → published → superseded'],
            ['published_scope_key', 'derived', 'not_applicable', null, '🛑 §18.21 idiom: at most one published per scope'],
            ['tokens', 'content', 'content', null, "this level's own token values; the tenant's design"],
            ['locks', 'content', 'content', null, "§8.14.1's per-path locks"],
            ['chrome', 'content', 'content', null, '🛑 §8.14.3 structured content, never HTML'],
            ['email', 'content', 'content', null, "§8.14.13's slot overrides"],
            ['content_hash', 'derived', 'not_applicable', null, "🛑 §8.14.4's immutable stylesheet address"],
            ['contrast', 'derived', 'not_applicable', null, "§8.14.5's report, both schemes"],
            ['contrast_verdict', 'derived', 'not_applicable', null, '🛑 refuse below 3:1 (§8.14.5)'],
            ['contrast_override', 'operational', 'not_applicable', null, '🛑 §8.14.5: the override is audited'],
            ['contrast_override_reason', 'content', 'content', null, "the operator's stated reason"],
            ['published_at', 'operational', 'not_applicable', null, null],
            ['published_by', 'pseudonymous', 'platform', null, 'who published it'],
            ['created_by', 'pseudonymous', 'platform', null, 'who drafted it'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('theme_assets', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'NULL at installation scope'],
            ['scope_type', 'operational', 'not_applicable', null, 'who may reference it'],
            ['scope_id', 'operational', 'not_applicable', null, 'NULL at installation scope'],
            ['scope_key', 'derived', 'not_applicable', null, '🛑 §18.21 COALESCE sentinel'],
            ['kind', 'operational', 'not_applicable', null, '🛑 closed: each kind is a distinct re-encoding path'],
            ['content_hash', 'derived', 'not_applicable', null, '🛑 §8.14.11: over the bytes DocUp wrote, not received'],
            ['media_type', 'operational', 'not_applicable', null, 'always a type DocUp produced itself'],
            ['byte_size', 'operational', 'not_applicable', null, null],
            ['width', 'operational', 'not_applicable', null, 'after re-encoding; NULL for a font'],
            ['height', 'operational', 'not_applicable', null, 'after re-encoding; NULL for a font'],
            ['source_media_type', 'operational', 'not_applicable', null, 'what was sniffed from the upload'],
            ['label', 'content', 'content', null, "🛑 the operator's label; the filename is discarded (§8.14.11)"],
            ['created_by', 'pseudonymous', 'platform', null, 'who uploaded it'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('theme_assignments', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'the tenancy key; carries the cascade'],
            ['scope_type', 'operational', 'not_applicable', null, 'installation or organisation'],
            ['scope_id', 'operational', 'not_applicable', null, '🛑 no FK: the sentinel is generated from it'],
            ['scope_key', 'derived', 'not_applicable', null, '🛑 §18.21 COALESCE sentinel; makes the unique index total'],
            ['name', 'content', 'content', null, "the operator's name for the binding"],
            ['theme_revision_id', 'operational', 'not_applicable', null, '🛑 RESTRICT: a delete would restyle every mount'],
            ['created_by', 'pseudonymous', 'platform', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);
    }

    public function down(): void
    {
        DataClassification::forget('theme_assignments');
        DataClassification::forget('theme_assets');
        DataClassification::forget('theme_revisions');
        DataClassification::forget('token_definitions');

        Schema::table('domain_mounts', function (Blueprint $table): void {
            $table->dropForeign(['theme_assignment_id']);
        });

        Schema::dropIfExists('theme_assignments');
        Schema::dropIfExists('theme_assets');
        Schema::dropIfExists('theme_revisions');
        Schema::dropIfExists('token_definitions');
    }
};
