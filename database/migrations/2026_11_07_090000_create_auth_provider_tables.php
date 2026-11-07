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
 * §8.12.2's one bindings table and §8.12.16's reader credentials (§10.6).
 *
 * > "Every authentication and authorisation mechanism MUST be a plugin instance
 * > in **one** `auth_provider_bindings` table with a driver type string,
 * > non-secret JSON config, a `config_version`, and envelope-encrypted secrets
 * > no API or UI ever returns. Third-party drivers MUST be installable without
 * > migrations."
 *
 * 🛑 **"Without migrations" is what makes this one table rather than one per
 * driver.** A `type` string plus a JSON config means a third-party driver ships
 * as a class and a registry entry; a column per driver would mean a migration
 * per driver, and the first thing an operator would do is edit the schema of a
 * table the application validates against.
 *
 * 🛑 **No domain dimension**, and §10.6 says why: "one fixed callback per
 * binding was measured to serve readers originating from two different custom
 * domains, because the identity provider never learns which host began the
 * flow (ADR 0008)". §18.9 verified that on Keycloak 26.0.8. A `domain_id` here
 * would have been the schema admitting a problem the measurement says does not
 * exist — and would have multiplied every operator's IdP administration by the
 * number of their domains.
 */
return new class extends Migration
{
    public function up(): void
    {
        /*
         * §8.12.3: "Bindings MUST be scoped at installation, organisation or
         * project level with most-specific-of-type resolution, so one
         * installation Okta binding serves 200 projects while project 201
         * brings its own Entra tenant."
         */
        Schema::create('auth_provider_bindings', function (Blueprint $table): void {
            $table->uuidKey();

            /*
             * 🛑 Nullable, because an installation-scoped binding belongs to no
             * organisation. That is the same shape `role_assignments` has and
             * the same reason: §12.1's installation scope is above tenancy, so
             * a NOT NULL tenant key here would make the top of the chain
             * unrepresentable.
             */
            $table->uuidForeign('organisation_id', nullable: true);

            $table->enum('scope_type', ['installation', 'organisation', 'project']);
            $table->uuidForeign('scope_id', nullable: true, index: false);

            /*
             * 🛑 §8.12.3's uniqueness, made total with P02's verified idiom.
             *
             * `UNIQUE (scope_type, scope_id, name)` — §10.6's own spelling —
             * would be satisfied by any number of installation bindings called
             * the same thing, because MySQL permits unlimited NULLs in a unique
             * index and installation scope has a NULL `scope_id`. §18.21 leaves
             * the partial-uniqueness idioms unverified, so this does what
             * `role_assignments.scope_key` does instead: COALESCE to a zero
             * sentinel, which is never NULL and therefore total under any
             * behaviour §18.21 turns out to have.
             */
            $table->binary('scope_key', 16, true)
                ->storedAs("COALESCE(scope_id, UNHEX(REPEAT('0', 32)))");

            /*
             * The provider's own sub-tenant, where it has one — a Keycloak
             * realm, an Entra tenant id, an LDAP base DN. Non-secret and in its
             * own column rather than inside `config` because §8.12.18's `iss`
             * check compares against it and a validation invariant should not
             * have to reach into a JSON blob.
             */
            $table->string('realm', 190)->nullable();

            /*
             * 🛑 The driver type, as a **string** and not an enum.
             *
             * §8.12.2's "Third-party drivers MUST be installable without
             * migrations" forbids an enum here: an enum is a schema change per
             * driver. What constrains the value is
             * {@see \App\Auth\Providers\DriverRegistry}, which refuses a type it
             * does not know — and §8.12.4's installation-level restriction,
             * which narrows the set an operator may configure further still.
             */
            $table->string('type', 64);

            /** The operator's own name for it; §8.12.19's 503 names the binding. */
            $table->string('name', 120);

            /*
             * Non-secret configuration. 🛑 The split is the requirement: a
             * client id is config and a client secret is a secret, and the
             * difference is that an API may return the first.
             */
            $table->json('config');

            /*
             * §8.12.2's `config_version`. Bumped on every write, so a cached
             * driver instance can be invalidated by comparison rather than by
             * a purge — the same mechanism §10.8's epochs use.
             */
            $table->unsignedInteger('config_version')->default(1);

            /*
             * 🛑 §9.1.7's envelope columns, which are §10.6's `secrets BLOB,
             * secrets_key_id` written in the construction §9.1.7 fixes.
             *
             * `wrapped_key` and `ciphertext` are the sealed material;
             * `kek_fingerprint` is the `secrets_key_id` — which KEK wrapped this
             * record, so a rotation can find what it has not reached and a
             * decrypt can skip keys that cannot be right. All four nullable
             * because most drivers hold no secret at all: `public` and
             * `ip_allowlist` have nothing to seal, and a binding with an empty
             * envelope is different from one whose envelope will not open.
             */
            $table->unsignedSmallInteger('envelope_version')->nullable();
            $table->string('kek_fingerprint', 64)->collation('ascii_bin')->nullable();
            $table->binary('wrapped_key', 255, false)->nullable();
            $table->binary('ciphertext', 8192, false)->nullable();

            /*
             * 🛑 Whether a share link may be minted against this binding
             * (§10.6's `shareable`). Default **false**: §8.12.16 gives a share
             * link mandatory expiry and a rate limiter, and a driver that has
             * not been thought about in those terms must not acquire a
             * credential class by default.
             */
            $table->boolean('shareable')->default(false);

            /*
             * 🛑 §8.12.19's five states, in order: "Bindings MUST progress
             * `draft → verifying → active → degraded → disabled`, and MUST NOT
             * leave `verifying` until an automated probe passes **and** a human
             * completes a test login."
             *
             * `draft` by default, so a half-configured binding authenticates
             * nobody. The two conditions for leaving `verifying` are
             * `probe` below and `verified_by`/`verified_at` — a row, not a
             * promise.
             */
            $table->enum('state', ['draft', 'verifying', 'active', 'degraded', 'disabled'])
                ->default('draft');

            /*
             * The last probe's result: what was checked, when, and what it
             * said. JSON because a probe's shape is the driver's — an OIDC
             * discovery document's issuer is not an LDAP bind's result — and
             * §8.12.19 only requires that it passed.
             */
            $table->json('probe')->nullable();

            /*
             * 🛑 Consecutive failures, which is what moves `active` →
             * `degraded`. A counter rather than a timestamp because the
             * transition is about repetition: one failed probe is a network,
             * and five is a provider.
             */
            $table->unsignedSmallInteger('probe_failures')->default(0);

            /*
             * §10.6's `epoch`. Bumped on every config or state change, and read
             * by the driver cache — so a binding edit takes effect on the next
             * request with no purge, exactly as §10.8's epochs do for policy.
             */
            $table->unsignedBigInteger('epoch')->default(0);

            /*
             * 🛑 §8.12.19's human half: "MUST NOT leave `verifying` until an
             * automated probe passes **and** a human completes a test login".
             *
             * The user who completed it, and when. Two columns rather than a
             * boolean, because "who said this provider works" is the question
             * an incident asks and a boolean cannot answer.
             */
            $table->uuidForeign('verified_by', nullable: true);
            $table->datetime('verified_at', 3)->nullable();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique(['scope_type', 'scope_key', 'name'], 'auth_provider_bindings_name_unique');

            /*
             * §8.12.3's resolution query: every binding that bears on a target,
             * which the resolver then narrows to the most specific of each
             * type.
             */
            $table->index(['scope_type', 'scope_key'], 'auth_provider_bindings_scope_index');
            $table->index(['type', 'state'], 'auth_provider_bindings_type_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('verified_by')->references('id')->on('users')->nullOnDelete();
        });

        /*
         * 🛑 §8.12.16's two credential classes, in one table.
         *
         * > "Reader credentials MUST include share-by-link (mandatory expiry,
         * > converted to a cookie on first use and 302'd to a clean URL) …  and
         * > `Authorization: Bearer` reader tokens with version and path scope,
         * > `max_uses` and revocation."
         *
         * One table because they are the same thing with two presentation
         * forms: a CSPRNG secret, a scope, an expiry and a use count. The
         * difference is where the secret travels — a query string once, or an
         * `Authorization` header every time — and that is `kind`.
         *
         * 🛑 A **password** is not here. It belongs to the binding, not to a
         * credential instance: §8.12.16 gives the `password` driver one secret
         * for everybody it admits, and putting it in this table would imply a
         * per-reader password, which is an account system §4.2 excludes.
         * A share link's *optional* password is here, because that one is
         * per-link.
         */
        Schema::create('reader_credentials', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_id', index: false);
            $table->uuidForeign('binding_id');

            $table->enum('kind', ['shared_link', 'reader_token']);

            /** Shown in the dashboard so an operator can revoke the right one. */
            $table->string('label', 120);

            /*
             * §9.1.4: CSPRNG, stored hashed, never UUIDv7. `tokenHash()` brings
             * the indexed prefix the project's one token-lookup idiom needs —
             * narrow on the prefix, compare the full hash with `hash_equals`.
             */
            $table->tokenHash('secret_hash');

            /*
             * 🛑 A share link's own password, optional, Argon2id.
             *
             * §8.12.16: "Share-link password attempts MUST be rate-limited with
             * lockout and timing-safe comparison." Per link rather than per
             * binding, because the point of a passworded link is that the URL
             * alone is not enough — and two links from one binding should be
             * able to differ.
             */
            $table->string('password_hash', 255)->nullable();

            /*
             * §8.12.16's "version and path scope", which §12.3's last conjunct
             * applies when this credential is the satisfying leaf.
             */
            $table->json('version_selector');
            $table->json('path_patterns');

            /*
             * 🛑 §8.12.16 makes expiry **mandatory** for a share link. Enforced
             * by the CHECK below rather than by the application, because a link
             * with no expiry is a permanent public URL for private content and
             * the whole class of mistake is forgetting to set one.
             */
            $table->datetime('expires_at', 3)->nullable();

            /** §8.12.16's `max_uses`; null is unlimited within the expiry. */
            $table->unsignedInteger('max_uses')->nullable();
            $table->unsignedInteger('uses')->default(0);

            $table->datetime('last_used_at', 3)->nullable();

            /** §8.12.16's revocation. Set rather than deleted; see docs_sessions. */
            $table->datetime('revoked_at', 3)->nullable();
            $table->string('revoked_reason', 64)->nullable();

            $table->uuidForeign('created_by', nullable: true);

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            /* The lookup: every live credential for a project, by kind. */
            $table->index(['project_id', 'kind', 'revoked_at'], 'reader_credentials_lookup_index');

            /* The expiry sweep. */
            $table->index('expires_at', 'reader_credentials_expiry_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_id')->references('id')->on('projects')->cascadeOnDelete();

            /*
             * 🛑 **RESTRICT, not cascade**, and it is §8.12.19's own sentence:
             * "A referenced binding MUST NOT be deletable." A cascade would
             * delete every share link an operator issued the moment they tidied
             * up a binding, silently; `restrict` makes the database refuse the
             * delete and the operator revoke the links first.
             */
            $table->foreign('binding_id')->references('id')->on('auth_provider_bindings')->restrictOnDelete();

            $table->foreign('created_by')->references('id')->on('users')->nullOnDelete();
        });

        /*
         * 🛑 §8.12.16's mandatory expiry, as the database refusing a link
         * without one.
         *
         * Raw DDL because Laravel's schema builder has no portable CHECK, and
         * this is not portable advice: a share link with no expiry is a
         * permanent URL that serves private documentation to anybody who has
         * ever seen it.
         */
        DB::statement(
            "ALTER TABLE `reader_credentials`
               ADD CONSTRAINT `reader_credentials_link_expires`
               CHECK (`kind` <> 'shared_link' OR `expires_at` IS NOT NULL)",
        );

        /*
         * 🛑 And a password only on a link. §8.12.16 gives the password to a
         * share link; a bearer token's secret *is* the credential, so a second
         * factor on it would be a password nobody is prompted for.
         */
        DB::statement(
            "ALTER TABLE `reader_credentials`
               ADD CONSTRAINT `reader_credentials_password_on_link`
               CHECK (`password_hash` IS NULL OR `kind` = 'shared_link')",
        );

        /*
         * 🛑 P22's deferred foreign key, now that the parent exists.
         *
         * `reader_identities.binding_id` shipped with the column shape and the
         * unique key but no constraint, because `auth_provider_bindings` did
         * not exist — the expand half of §10.9's expand/contract rule, with the
         * contract half dated in that migration's own comment. This is it.
         *
         * `restrictOnDelete` for the same reason the credentials' is: §8.12.19
         * forbids deleting a referenced binding, and a cascade would erase the
         * identities a provider vouched for along with the provider.
         */
        Schema::table('reader_identities', function (Blueprint $table): void {
            $table->foreign('binding_id')
                ->references('id')
                ->on('auth_provider_bindings')
                ->restrictOnDelete();
        });

        DataClassification::annotate('auth_provider_bindings', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'NULL at installation scope (§12.1)'],
            ['scope_type', 'operational', 'not_applicable', null, '🛑 §8.12.3 most-specific-of-type resolution'],
            ['scope_id', 'operational', 'not_applicable', null, 'NULL at installation scope'],
            ['scope_key', 'derived', 'not_applicable', null, '🛑 COALESCE sentinel; makes the unique index total'],
            ['realm', 'operational', 'not_applicable', null, "the provider's own sub-tenant; §8.12.18 compares iss"],
            ['type', 'operational', 'not_applicable', null, '🛑 §8.12.2: a string, so a driver needs no migration'],
            ['name', 'content', 'content', null, "the operator's own name; §8.12.19's 503 names it"],
            ['config', 'operational', 'not_applicable', null, '🛑 NON-SECRET only; secrets are sealed below'],
            ['config_version', 'operational', 'not_applicable', null, '§8.12.2; invalidates a cached driver'],
            ['envelope_version', 'operational', 'not_applicable', null, '§9.1.7 envelope construction version'],
            ['kek_fingerprint', 'operational', 'not_applicable', null, "§10.6's secrets_key_id: which KEK wrapped this"],
            ['wrapped_key', 'secret', 'not_applicable', 'credentials', '🛑 §9.1.7 data key, sealed under the KEK'],
            ['ciphertext', 'secret', 'not_applicable', 'credentials', '🛑 §8.12.2: no API or UI ever returns this'],
            ['shareable', 'operational', 'not_applicable', null, '🛑 default false; a share link is a credential class'],
            ['state', 'operational', 'not_applicable', null, '🛑 §8.12.19 five states, draft by default'],
            ['probe', 'operational', 'not_applicable', null, '§8.12.19: the automated half of activation'],
            ['probe_failures', 'operational', 'not_applicable', null, 'consecutive; moves active → degraded'],
            ['epoch', 'operational', 'not_applicable', null, '§10.8: invalidates the driver cache on a write'],
            ['verified_by', 'pseudonymous', 'platform', null, '🛑 §8.12.19: who completed the test login'],
            ['verified_at', 'operational', 'not_applicable', null, '🛑 §8.12.19: and when'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('reader_credentials', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['project_id', 'operational', 'not_applicable', null, null],
            ['binding_id', 'operational', 'not_applicable', null, '🛑 §8.12.19: RESTRICT, not cascade'],
            ['kind', 'operational', 'not_applicable', null, '§8.12.16: shared_link or reader_token'],
            ['label', 'content', 'content', null, 'shown so an operator can revoke the right one'],
            ['secret_hash', 'secret', 'not_applicable', null, '🛑 §9.1.4: CSPRNG, stored hashed'],
            ['secret_hash_prefix', 'secret', 'not_applicable', null, 'indexed lookup prefix of the hash'],
            ['password_hash', 'secret', 'not_applicable', null, '🛑 §8.12.16: Argon2id, per link, rate-limited'],
            ['version_selector', 'operational', 'not_applicable', null, '§8.12.16 version scope'],
            ['path_patterns', 'content', 'content', null, '§8.12.16 path scope; §12.3 applies it'],
            ['expires_at', 'operational', 'not_applicable', null, '🛑 §8.12.16: mandatory for a share link (CHECK)'],
            ['max_uses', 'operational', 'not_applicable', null, '§8.12.16'],
            ['uses', 'operational', 'not_applicable', null, null],
            ['last_used_at', 'personal', 'platform', null, 'when this credential was last presented'],
            ['revoked_at', 'operational', 'not_applicable', null, '§8.12.16 revocation'],
            ['revoked_reason', 'operational', 'not_applicable', null, 'fixed vocabulary, never free text'],
            ['created_by', 'pseudonymous', 'platform', null, 'the operator who issued it'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);
    }

    public function down(): void
    {
        DataClassification::forget('reader_credentials');
        DataClassification::forget('auth_provider_bindings');

        Schema::table('reader_identities', function (Blueprint $table): void {
            $table->dropForeign(['binding_id']);
        });

        Schema::dropIfExists('reader_credentials');
        Schema::dropIfExists('auth_provider_bindings');
    }
};
