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
 * §8.12.18's OIDC exchange and §10.6's `provider_group_mappings`.
 *
 * Three changes, and the first is the one §10.6 does not name.
 *
 * ## 🛑 `oidc_authorisation_requests` — a proposed §10.6 addition
 *
 * §8.12.18 requires "PKCE S256 mandatory, `state` bound to the originating
 * domain, single-use `nonce`". Those three facts have to survive a round trip
 * through an identity provider, and there are only two places they can live:
 * the dashboard's own session, or a row.
 *
 * **The session was rejected.** A reader arriving at an OIDC binding is *not*
 * signed in to the dashboard — that is the whole point of the driver — so the
 * only session available is the anonymous one Laravel starts for any web
 * request. Three things make it the wrong home:
 *
 * 1. **Single-use is not expressible.** A session holds one value per key, so a
 *    reader opening two guarded projects in two tabs has the second flow
 *    overwrite the first's `nonce`. §8.12.18's "single-use" becomes
 *    "last-one-wins", which is a different property.
 * 2. **No replay latch.** `reader_handoff_codes` consumes its code in one
 *    atomic conditional `UPDATE` (§8.12.10, corpus case `reader-001`). A
 *    session read-modify-write has the race that latch exists to close.
 * 3. **No audit trail.** §8.12.18's seven rejections must each raise a
 *    *distinct* audit event, and a rejection needs the row it was judged
 *    against to say which binding and which domain it concerned.
 *
 * So this table is `reader_handoff_codes`' sibling, built the same way and for
 * the same reasons: a hashed single-use secret, a short expiry, an attempt
 * counter, and the originating domain stored server-side so the return address
 * is never taken from a parameter.
 *
 * 🛑 **The PKCE verifier is stored, and that is safe here in a way it would not
 * be for §8.12.10's handoff.** This verifier belongs to the *IdP* leg, which
 * DocUp conducts itself from its own back channel — nobody else ever holds it,
 * and binding it to the browser would buy nothing because the browser is not a
 * party to the token exchange. §8.12.10's verifier is the opposite case: it
 * exists precisely so a leaked code is useless to anybody but the browser that
 * asked, so it lives in a `__Host-` cookie on the documentation origin and
 * never in a row.
 *
 * ## `provider_group_mappings`
 *
 * §10.6 names it; §8.12.5 and §8.13.7 say what it must refuse. Its own comment
 * below carries the project-scope rule.
 *
 * ## `reader_handoff_codes` learns about readers
 *
 * P22 built the handoff for a dashboard **user** and typed `user_id` NOT NULL
 * accordingly, because in P22 every reader was a member or anonymous. An
 * IdP-vouched reader is neither, so the column becomes nullable beside a new
 * `reader_identity_id` with a CHECK that exactly one is set — the same shape
 * `docs_sessions` already carries, for the same reason.
 */
return new class extends Migration
{
    public function up(): void
    {
        /*
         * 🛑 §8.12.18's in-flight state. Everything the callback needs in order
         * to judge what comes back, written before the reader leaves.
         */
        Schema::create('oidc_authorisation_requests', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');

            /*
             * 🛑 The binding, `restrictOnDelete` for §8.12.19's reason: a
             * referenced binding is not deletable, and an in-flight exchange is
             * a reference. A cascade would let an operator delete a binding
             * mid-login and have the callback find nothing to judge against,
             * which is indistinguishable from a forged `state`.
             */
            $table->uuidForeign('binding_id');

            /*
             * Where the reader came from and where they are going back to.
             * §8.12.10: "the return URL built **from the verified domain row,
             * never from a request parameter**" — so the domain is stored here
             * and the callback reads it from the row, never from the IdP's
             * redirect.
             */
            $table->uuidForeign('domain_id');
            $table->uuidForeign('project_id', index: false);

            /*
             * 🛑 `state`, hashed. §9.1.4: "security tokens are CSPRNG, stored
             * hashed, and never UUIDv7". `state` is a security token — it is
             * the CSRF defence for the authorisation request — so it is stored
             * the way every other one in this schema is. `tokenHash()` writes
             * the digest column and its indexed `_prefix` together, which is
             * why neither is spelled out here: the prefix is the lookup and
             * `hash_equals` is the comparison.
             */
            $table->tokenHash('state_hash');

            /*
             * 🛑 `nonce`, hashed, and single-use by the `consumed_at` latch
             * below rather than by deletion. §8.12.18 wants a single-use nonce;
             * keeping the row after it is spent is what lets a *replay* be
             * reported as a replay instead of as an unknown state.
             */
            $table->tokenHash('nonce_hash');

            /*
             * The IdP leg's PKCE verifier. See the class note: this one is
             * DocUp's own and travels only on DocUp's back channel.
             */
            $table->string('code_verifier', 128)->collation('ascii_bin');

            /*
             * §8.12.10's challenge, carried through so the callback can mint a
             * handoff code the documentation origin will accept. 43 base64url
             * characters, the same shape `reader_handoff_codes` stores.
             */
            $table->char('handoff_challenge', 43)->collation('ascii_bin');

            /*
             * Where in the documentation the reader was going. Normalised by
             * `ReaderHandoff::safeReturnPath()` before it is written, so a
             * malicious `return` cannot be stored and replayed later.
             */
            $table->string('return_path', 512);

            $table->datetime('expires_at', 3);
            $table->datetime('consumed_at', 3)->nullable();

            /*
             * 🛑 Bounded attempts, like the handoff's. A `state` that resolves
             * but whose exchange fails is either a broken IdP or somebody
             * probing; either way the row must not be retriable indefinitely.
             */
            $table->unsignedTinyInteger('attempts')->default(0);

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique('state_hash', 'oidc_requests_state_unique');
            $table->index('expires_at', 'oidc_requests_expiry_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('binding_id')->references('id')->on('auth_provider_bindings')->restrictOnDelete();
            $table->foreign('domain_id')->references('id')->on('domains')->cascadeOnDelete();
            $table->foreign('project_id')->references('id')->on('projects')->cascadeOnDelete();
        });

        /*
         * 🛑 §8.12.5's group mappings, with the refusal in the schema as well
         * as in the code.
         *
         * > "Project-scoped bindings MUST NOT produce any dashboard role,
         * > enforced both as a driver capability flag and as a validation
         * > invariant on group mappings."
         *
         * `target` is what the mapping produces: a dashboard `role` (installation
         * and organisation scope only) or a reader `group` (any scope). The
         * CHECK below makes the first impossible to write for a project-scoped
         * binding — not because the application would allow it, but because
         * "enforced both as" means two enforcements, and a database CHECK is
         * the one that survives a future writer who did not read §8.12.5.
         */
        Schema::create('provider_group_mappings', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id', nullable: true);
            $table->uuidForeign('binding_id');

            /*
             * Denormalised from the binding so the CHECK can see it. A CHECK
             * cannot subquery, so the scope has to be on the row — and
             * `Bindings` is the only writer, which is what keeps it true.
             */
            $table->string('binding_scope_type', 16)->collation('ascii_bin');

            /* The claim value as the provider sends it. */
            $table->string('provider_group', 255);

            $table->enum('target', ['role', 'group']);

            /*
             * One of §12.1's ten fixed roles when `target = 'role'`, or a
             * reader group name when `target = 'group'`. Not an ENUM of the
             * roles: §12.1's list is code-enumerable and `RoleRegistry` is
             * where it lives, so an ENUM here would be a second copy that
             * drifts.
             */
            $table->string('target_value', 64)->collation('ascii_bin');

            /*
             * The scope a mapped role lands on. NULL for `target = 'group'`,
             * which is not scoped: a reader group is a fact about the reader,
             * and §12.3's rules are what give it meaning per project.
             */
            $table->string('scope_type', 16)->nullable()->collation('ascii_bin');
            $table->binary('scope_id', 16, true)->nullable();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique(
                ['binding_id', 'provider_group', 'target', 'target_value'],
                'provider_group_mappings_unique',
            );
            $table->index('binding_id', 'provider_group_mappings_binding_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('binding_id')->references('id')->on('auth_provider_bindings')->cascadeOnDelete();
        });

        /*
         * 🛑 §8.12.5, in the database. A project-scoped binding may map a
         * reader group and may not map a dashboard role.
         */
        DB::statement(
            'ALTER TABLE `provider_group_mappings` ADD CONSTRAINT '
            .'`provider_group_mappings_project_scope_no_role` CHECK ('
            ."`target` <> 'role' OR `binding_scope_type` <> 'project')"
        );

        /*
         * 🛑 And a mapped role must name a scope, because §12.1 resolves roles
         * over the scope chain and a role assignment with no scope is one the
         * resolver cannot place.
         */
        DB::statement(
            'ALTER TABLE `provider_group_mappings` ADD CONSTRAINT '
            .'`provider_group_mappings_role_needs_scope` CHECK ('
            ."(`target` = 'role') = (`scope_type` IS NOT NULL))"
        );

        /*
         * P22's handoff learns that a reader need not be a `User`.
         *
         * 🛑 The FK is dropped and rebuilt rather than altered in place:
         * MySQL will not change a column's nullability while a foreign key
         * references it, and `change()` without the drop fails with an error
         * that names the constraint and not the cause.
         */
        Schema::table('reader_handoff_codes', function (Blueprint $table): void {
            $table->dropForeign(['user_id']);
        });

        Schema::table('reader_handoff_codes', function (Blueprint $table): void {
            /*
             * 🛑 Spelled out rather than `uuidForeign(...)->change()`: that
             * macro returns `void`, so the chained call would be on null. The
             * shape it writes is `binary(16, fixed: true)`, reproduced here so
             * the altered column keeps exactly the type the others have.
             */
            $table->binary('user_id', 16, true)->nullable()->change();
            $table->uuidForeign('reader_identity_id', nullable: true, index: false);
        });

        Schema::table('reader_handoff_codes', function (Blueprint $table): void {
            $table->foreign('user_id')->references('id')->on('users')->cascadeOnDelete();
            $table->foreign('reader_identity_id')->references('id')->on('reader_identities')->cascadeOnDelete();
        });

        /*
         * 🛑 Exactly one subject, the same CHECK `docs_sessions` carries. §8.12.1
         * makes the two principal populations "physically disjoint", and a row
         * naming both would be the one place they met.
         */
        DB::statement(
            'ALTER TABLE `reader_handoff_codes` ADD CONSTRAINT '
            .'`reader_handoff_codes_one_subject` CHECK ('
            .'(`user_id` IS NULL) <> (`reader_identity_id` IS NULL))'
        );

        DataClassification::annotate('oidc_authorisation_requests', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['binding_id', 'operational', 'not_applicable', null, '🛑 §8.12.19: RESTRICT, not cascade'],
            ['domain_id', 'operational', 'not_applicable', null, '🛑 §8.12.10: the return address, server-side'],
            ['project_id', 'operational', 'not_applicable', null, null],
            ['state_hash', 'secret', 'not_applicable', null, '🛑 §9.1.4: CSPRNG, stored hashed'],
            ['state_hash_prefix', 'secret', 'not_applicable', null, 'indexed lookup prefix of the hash'],
            ['nonce_hash', 'secret', 'not_applicable', null, '🛑 §8.12.18: single-use, by the consumed_at latch'],
            ['nonce_hash_prefix', 'secret', 'not_applicable', null, "tokenHash()'s prefix; the nonce is found by state, not by this"],
            ['code_verifier', 'secret', 'not_applicable', null, "🛑 §8.12.18: S256; DocUp's own back-channel leg"],
            ['handoff_challenge', 'secret', 'not_applicable', null, "§8.12.10's challenge, carried through"],
            ['return_path', 'content', 'content', null, 'normalised before storage, never replayed raw'],
            ['expires_at', 'operational', 'not_applicable', null, 'short; an authorisation request is not durable'],
            ['consumed_at', 'operational', 'not_applicable', null, '🛑 §8.12.18: the single-use latch'],
            ['attempts', 'operational', 'not_applicable', null, 'bounded, like the handoff code'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('provider_group_mappings', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'NULL at installation scope (§12.1)'],
            ['binding_id', 'operational', 'not_applicable', null, null],
            ['binding_scope_type', 'operational', 'not_applicable', null, '🛑 §8.12.5: denormalised so the CHECK can see it'],
            ['provider_group', 'content', 'content', null, "the provider's own group name, as it sends it"],
            ['target', 'operational', 'not_applicable', null, '🛑 §8.12.5: role (not at project scope) or group'],
            ['target_value', 'operational', 'not_applicable', null, "§12.1's fixed role, or a reader group name"],
            ['scope_type', 'operational', 'not_applicable', null, '§12.1 scope chain; NULL for a reader group'],
            ['scope_id', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        /*
         * One added column, not the whole table. `annotate()` upserts on
         * `(table, column)`, so this adds the new row and leaves P22's
         * fifteen alone.
         */
        DataClassification::annotate('reader_handoff_codes', [
            ['reader_identity_id', 'pseudonymous', 'platform', null, '🛑 §8.12.1: the other principal population'],
        ]);
    }

    public function down(): void
    {
        DataClassification::forget('provider_group_mappings');
        DataClassification::forget('oidc_authorisation_requests');

        /*
         * 🛑 Named, because this migration added a column to a table it did
         * not create. The whole-table form would strip P22's annotations and
         * `classify --check` would then fail on columns nobody touched.
         */
        DataClassification::forget('reader_handoff_codes', ['reader_identity_id']);

        DB::statement('ALTER TABLE `reader_handoff_codes` DROP CHECK `reader_handoff_codes_one_subject`');

        Schema::table('reader_handoff_codes', function (Blueprint $table): void {
            $table->dropForeign(['reader_identity_id']);
            $table->dropForeign(['user_id']);
            $table->dropColumn('reader_identity_id');
        });

        Schema::table('reader_handoff_codes', function (Blueprint $table): void {
            $table->binary('user_id', 16, true)->nullable(false)->change();
        });

        Schema::table('reader_handoff_codes', function (Blueprint $table): void {
            $table->foreign('user_id')->references('id')->on('users')->cascadeOnDelete();
        });

        Schema::dropIfExists('provider_group_mappings');
        Schema::dropIfExists('oidc_authorisation_requests');
    }
};
