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
 * §8.12.1's disjoint reader population, §12.4's server-side sessions, §8.12.10's
 * handoff and §8.12.11's grant keys (§10.7, §10.8).
 *
 * 🛑 **`reader_identities` and `users` are two tables and there is no column
 * joining them**, which is what §8.12.1's "physically disjoint" means and the
 * reason it is stated as a schema property rather than a policy:
 *
 * > "Reader identities MUST be keyed `(binding_id, subject_hash)`, **email MUST
 * > NEVER be used for linking or lookup**, and a reader identity MUST NEVER hold
 * > a role assignment … A project admin controls their own IdP;
 * > find-or-create-by-email would let any tenant mint an installation owner."
 *
 * The "never holds a role assignment" half is already enforced by a table
 * created in P02: `role_assignments.subject_type` is `ENUM('user', 'group',
 * 'api_token')`, so a row naming a reader identity cannot be stored at all. That
 * is the strongest form the rule can take, and it costs nothing here — which is
 * why this migration adds no `subject_type` of its own.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('projects', function (Blueprint $table): void {
            /*
             * §10.8's `identity_epoch`, owed since P02's registry declared it.
             *
             * Bumped by "reader deprovision, group change, session revoke", and
             * per-project for the reason `authz_epoch` is: §8.9.10 refuses to
             * let "one project's domain change … invalidate every other
             * project's resolution cache", and the same argument applies to a
             * session revoke. An installation-wide identity counter would make
             * one reader's logout invalidate every grant on the installation.
             */
            $table->unsignedBigInteger('identity_epoch')->default(0)->after('policy_generation');
        });

        /*
         * 🛑 §8.12.1's second principal population.
         *
         * `binding_id` carries **no foreign key**, and the absence is dated:
         * `auth_provider_bindings` is P23's first deliverable (§17), so a
         * constraint written here would reference a table that does not exist.
         * The column shape and the unique key are final; P23 adds the
         * constraint in the migration that creates the parent, which is the
         * expand half of §10.9's expand/contract rule.
         */
        Schema::create('reader_identities', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');

            /*
             * 🛑 Half of §8.12.1's key. A reader is identified by *which
             * binding vouched for them* and by an opaque subject, never by a
             * mailbox: "email MUST NEVER be used for linking or lookup".
             */
            $table->uuidForeign('binding_id');

            /*
             * 🛑 The other half, and 🛑 **hashed rather than stored**. §9.1.4
             * requires security tokens to be stored hashed; a provider subject
             * is not a token, but it is an identifier belonging to somebody
             * else's directory, and a keyed digest is sufficient for the only
             * operation this column supports — equality on login.
             *
             * BINARY(32) because it is a SHA-256 digest, not a string, so the
             * column cannot accidentally hold a readable subject.
             */
            $table->binary('subject_hash', 32, false);

            /*
             * What the UI may show about this reader (§8.12.25's simulator
             * names an identity). Nullable because a provider need not supply
             * one, and 🛑 deliberately **not** an email column: §8.12.1 forbids
             * email for linking or lookup, and a column present for display is
             * one `WHERE` away from being used for lookup.
             */
            $table->string('display_label', 120)->nullable();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();
            $table->datetime('last_seen_at', 3)->nullable();

            /*
             * §8.12.26's deprovisioning, which §10.8 makes a trigger for
             * `identity_epoch`. Set rather than deleted, because the audit
             * trail refers to the identity and §20.3 retains decisions for 90
             * days after the row stops being usable.
             */
            $table->datetime('deprovisioned_at', 3)->nullable();

            $table->unique(['binding_id', 'subject_hash'], 'reader_identities_subject_unique');
            $table->index(['organisation_id', 'deprovisioned_at'], 'reader_identities_tenant_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
        });

        /*
         * §12.4's `docs_sessions`: "opaque handle to a server-side revocable
         * `docs_sessions` row", and §19 decision 17's reason for its existence:
         *
         * > "Reader sessions are **server-side and revocable**, behind an opaque
         * > refresh cookie, with a short-lived grant as the per-request bearer.
         * > Stateless-only cannot satisfy SCIM offboarding or session inventory;
         * > grant-only cannot be revoked. Both are needed."
         *
         * 🛑 **Per origin, not per reader.** The row is keyed on the domain as
         * well as the project, because §8.12.10's whole mechanism is that each
         * documentation origin establishes its *own* session — so logging out of
         * project A cannot touch project B, and a session on domain A is not a
         * session on domain B even for the same project and the same person.
         */
        Schema::create('docs_sessions', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            /* Indexed by the composite below, which the foreign key reuses. */
            $table->uuidForeign('project_id', index: false);
            $table->uuidForeign('domain_id');

            /*
             * 🛑 **Two nullable subject columns and exactly one is set**, which
             * is §8.12.1's disjointness expressed where a session could
             * otherwise quietly erase it.
             *
             * A single polymorphic `(subject_type, subject_id)` pair would hold
             * both populations in one column and make "is this a reader or a
             * dashboard user?" a string comparison — the shape that produces
             * find-or-create-by-email three phases later. Two columns, two
             * foreign keys, and a CHECK that refuses both and neither.
             *
             * `user_id` is the P22 case: a dashboard member who completed
             * §8.12.10's handoff, authorised through §12.3's `members` rung.
             * `reader_identity_id` is P23's, when a provider binding produces an
             * identity that was never a dashboard user.
             */
            $table->uuidForeign('user_id', nullable: true, index: false);
            $table->uuidForeign('reader_identity_id', nullable: true, index: false);

            /*
             * 🛑 §9.1.4: "Security tokens are CSPRNG, stored hashed, and
             * **never** UUIDv7." The cookie carries CSPRNG bytes; this holds
             * their digest, so a database read discloses no session handle and
             * a stolen backup grants nobody access.
             *
             * `tokenHash()` rather than a bare column, because the macro brings
             * the indexed prefix the project's one token-lookup idiom needs:
             * narrow to a candidate on the prefix, then compare the full hash
             * with `hash_equals`. A unique index on the hash would find the row
             * just as well and would make the comparison a `WHERE` — which is
             * the habit {@see \App\Support\SecretToken::matches()} exists to
             * keep out of the code where timing does matter.
             */
            $table->tokenHash('handle_hash');

            /*
             * §8.12.13's Tier B cache key: "an **opaque** cache-key cookie
             * carrying no session material, so one PHP call authorises a
             * 60-asset page".
             *
             * 🛑 Stored, and stored as a digest, for two different reasons. It
             * is stored because nginx keys a cached subrequest on the cookie's
             * value and the application has to be able to find the session that
             * value belongs to; it is a digest because the value is a bearer
             * credential for that lookup, exactly like the handle above.
             *
             * 🛑 And it is a **separate** secret from the handle, never derived
             * from it. The cache-key cookie's value appears in an nginx cache
             * key, which is written to disk in plaintext and keyed by a path an
             * operator can list; deriving it from the handle would put a
             * reversible function between a world-readable filename and a
             * session.
             */
            $table->tokenHash('cache_key_hash');

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();
            $table->datetime('last_seen_at', 3)->nullable();

            /*
             * §12.4's "8–24 h", as the two timestamps that sentence implies.
             *
             * 🛑 Two columns rather than one, the same correction P02 made to
             * the dashboard session: Laravel's single `lifetime` is an idle
             * timeout that every request renews, so an absolute ceiling has to
             * be a second column or a session renews forever.
             */
            $table->datetime('idle_expires_at', 3);
            $table->datetime('absolute_expires_at', 3);

            /*
             * §8.12.15's "Session inventory and per-session revocation are
             * required because SCIM offboarding needs them".
             *
             * Revoked rather than deleted: §20.3 keeps the decision log for 90
             * days and an auditor asking "why did this stop working" needs the
             * reason, which a deleted row cannot give.
             */
            $table->datetime('revoked_at', 3)->nullable();
            $table->string('revoked_reason', 64)->nullable();

            /*
             * The combined epoch this session was established under (§8.12.11's
             * "combined policy and identity epoch"). A grant minted from this
             * session carries the *current* combined epoch, not this one; this
             * column is what §8.12.25's simulator and an audit read to say when
             * the session's view of the policy was taken.
             */
            $table->unsignedBigInteger('established_epoch')->default(0);

            $table->unique('handle_hash', 'docs_sessions_handle_unique');
            $table->unique('cache_key_hash', 'docs_sessions_cache_key_unique');

            /*
             * The session inventory query: every live session for a project,
             * which is what a revoke-all and §8.12.15's inventory both read.
             */
            $table->index(['project_id', 'revoked_at'], 'docs_sessions_inventory_index');
            $table->index(['user_id', 'revoked_at'], 'docs_sessions_user_index');
            $table->index(['reader_identity_id', 'revoked_at'], 'docs_sessions_identity_index');

            /* The expiry sweep (§20.3's purge job) reads this one. */
            $table->index('absolute_expires_at', 'docs_sessions_expiry_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_id')->references('id')->on('projects')->cascadeOnDelete();
            $table->foreign('domain_id')->references('id')->on('domains')->cascadeOnDelete();
            $table->foreign('user_id')->references('id')->on('users')->cascadeOnDelete();
            $table->foreign('reader_identity_id')->references('id')->on('reader_identities')->cascadeOnDelete();
        });

        /*
         * 🛑 The CHECK that makes the two columns above a disjunction rather
         * than a suggestion. Raw DDL because Laravel's schema builder has no
         * portable CHECK, and this constraint is not portable advice — it is the
         * database refusing to hold a session that belongs to both populations
         * or to neither.
         */
        DB::statement(
            'ALTER TABLE `docs_sessions`
               ADD CONSTRAINT `docs_sessions_one_subject`
               CHECK ((`user_id` IS NULL) <> (`reader_identity_id` IS NULL))',
        );

        /*
         * 🛑 §8.12.10's handoff code: "a single-use handoff code expiring within
         * 30 seconds, bound to the resolved domain and project, with the return
         * URL built **from the verified domain row, never from a request
         * parameter**."
         *
         * A table rather than a cache entry, and that is deliberate. The code is
         * single-use, and "single-use" has to be an atomic conditional write —
         * `UPDATE … WHERE consumed_at IS NULL` returning one affected row. A
         * cache `get`-then-`forget` is two operations with a race between them,
         * and the thing the race decides is whether one code mints two sessions.
         */
        Schema::create('reader_handoff_codes', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('project_id');
            $table->uuidForeign('domain_id');

            /* The dashboard principal the code was minted for. */
            $table->uuidForeign('user_id');

            /* §9.1.4 again: CSPRNG in the URL, digest in the table. */
            $table->tokenHash('code_hash');

            /*
             * 🛑 The PKCE challenge, `S256` only (§8.12.18 makes "PKCE S256
             * mandatory" for OIDC and the same rule governs DocUp's own
             * handoff; a `plain` challenge is a parameter the caller controls
             * and therefore no proof at all).
             *
             * 43 characters is the base64url length of a 32-byte digest with
             * no padding, so the column itself refuses a truncated challenge.
             */
            $table->char('challenge', 43)->collation('ascii_bin');

            /*
             * 🛑 The path the reader goes back to, and 🛑 **a path, never a
             * URL**. §8.12.10 says the return URL is "built from the verified
             * domain row, never from a request parameter": the origin comes
             * from the `domain_id` above when the code is redeemed, and this
             * column holds only what follows it. A column that could hold
             * `https://evil.example/` would be an open redirect with a
             * database row behind it.
             */
            $table->string('return_path', 2048);

            $table->datetime('created_at', 3)->nullable();

            /* §8.12.10's "expiring within 30 seconds", as a stored deadline. */
            $table->datetime('expires_at', 3);

            /* Null until redeemed; the single-use latch. */
            $table->datetime('consumed_at', 3)->nullable();

            $table->unique('code_hash', 'reader_handoff_codes_code_unique');
            $table->index('expires_at', 'reader_handoff_codes_expiry_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('project_id')->references('id')->on('projects')->cascadeOnDelete();
            $table->foreign('domain_id')->references('id')->on('domains')->cascadeOnDelete();
            $table->foreign('user_id')->references('id')->on('users')->cascadeOnDelete();
        });

        /*
         * §8.12.11's signing keys and §17's "four-state key rotation".
         *
         * 🛑 The four states exist so that a verifier always holds a key
         * *before* it signs anything and *after* it stops:
         *
         *   `pending`  — published in the JWKS, signs nothing. A verifier that
         *                caches the document for five minutes has the key
         *                before the first grant it must verify arrives.
         *   `active`   — the one key that signs. At most one, enforced below.
         *   `retiring` — still published, signs nothing. Grants minted under it
         *                are still inside their ≤10-minute lifetime.
         *   `retired`  — absent from the JWKS. Kept as a row so an audit can
         *                name the key a historical decision was signed by.
         *
         * Collapsing `pending` would mean the first grant under a new key can
         * reach an edge whose JWKS cache predates it; collapsing `retiring`
         * would invalidate every unexpired grant the moment a rotation started.
         * Both failures are outages, and both are silent until a rotation.
         */
        Schema::create('grant_signing_keys', function (Blueprint $table): void {
            $table->uuidKey();

            /*
             * 🛑 **No `organisation_id`.** The grant keypair is the
             * installation's, not a tenant's: §8.12.11 puts the public keys at
             * one JWKS endpoint and §15's backup set names "the Ed25519 grant
             * keypair" in the singular. A per-tenant key would publish the
             * tenant list at a public URL.
             */

            /*
             * The JWKS `kid`. A digest of the public key rather than a counter,
             * so two installations never collide and the identifier cannot
             * imply an order that the states above already carry.
             */
            $table->string('kid', 64)->collation('ascii_bin');

            $table->enum('state', ['pending', 'active', 'retiring', 'retired']);

            /*
             * 🛑 Exactly one `active` key, enforced by the database using
             * §18.21's verified idiom: a unique index over a stored generated
             * column that is NULL for every other state, and MySQL permits
             * unlimited NULLs in a unique index.
             *
             * Without it, "which key signs?" is a query with an implicit
             * assumption — the same argument `certificates.active_host` makes —
             * and the day two rows are active, half the grants verify against a
             * key the edge fetched before the other one appeared.
             */
            $table->unsignedTinyInteger('active_marker')
                ->nullable()
                ->storedAs("IF(`state` = 'active', 1, NULL)");

            /* Raw 32 bytes of Ed25519 public key — published, so not sealed. */
            $table->binary('public_key', 32, false);

            /*
             * 🛑 §9.1.7's envelope columns. The private key is the one secret in
             * this product that mints read access to every private project, so
             * it is sealed exactly as §8.10.15 seals a certificate key — and
             * §8.12.12's "no symmetric key capable of minting a grant MUST
             * reach any edge component" is why it never leaves this table in
             * plaintext for anything but a signature.
             */
            $table->unsignedSmallInteger('envelope_version');
            $table->string('kek_fingerprint', 64)->collation('ascii_bin');
            $table->binary('wrapped_key', 255, false);
            $table->binary('ciphertext', 1024, false);

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();
            $table->datetime('activated_at', 3)->nullable();
            $table->datetime('retiring_at', 3)->nullable();
            $table->datetime('retired_at', 3)->nullable();

            $table->unique('kid', 'grant_signing_keys_kid_unique');
            $table->unique('active_marker', 'grant_signing_keys_active_unique');

            /* The JWKS query: every key a verifier should hold. */
            $table->index('state', 'grant_signing_keys_state_index');
        });

        DataClassification::annotate('projects', [
            ['identity_epoch', 'operational', 'not_applicable', null, '§10.8: reader deprovision, group change, session revoke'],
        ]);

        DataClassification::annotate('reader_identities', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['binding_id', 'operational', 'not_applicable', null, '🛑 §8.12.1 key half; FK arrives with P23 bindings'],
            ['subject_hash', 'pseudonymous', 'platform', null, '🛑 §8.12.1: keyed digest, never an email'],
            ['display_label', 'personal', 'platform', null, '🛑 display only; never used for lookup'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
            ['last_seen_at', 'personal', 'platform', null, 'last login, for the session inventory'],
            ['deprovisioned_at', 'operational', 'not_applicable', null, '§10.8: bumps identity_epoch'],
        ]);

        DataClassification::annotate('docs_sessions', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['project_id', 'operational', 'not_applicable', null, '🛑 §8.12.10: a session is per project'],
            ['domain_id', 'operational', 'not_applicable', null, '🛑 §8.12.10: and per origin'],
            ['user_id', 'pseudonymous', 'platform', null, '🛑 §8.12.1: exclusive of reader_identity_id'],
            ['reader_identity_id', 'pseudonymous', 'platform', null, '🛑 §8.12.1: exclusive of user_id'],
            ['handle_hash', 'secret', 'not_applicable', null, '🛑 §9.1.4: CSPRNG, stored hashed'],
            ['handle_hash_prefix', 'secret', 'not_applicable', null, 'indexed lookup prefix of the hash'],
            ['cache_key_hash', 'secret', 'not_applicable', null, '🛑 §8.12.13 Tier B key; a separate secret'],
            ['cache_key_hash_prefix', 'secret', 'not_applicable', null, 'indexed lookup prefix of the hash'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
            ['last_seen_at', 'personal', 'platform', null, 'for the session inventory'],
            ['idle_expires_at', 'operational', 'not_applicable', null, '§12.4: idle half of 8–24 h'],
            ['absolute_expires_at', 'operational', 'not_applicable', null, '§12.4: absolute ceiling'],
            ['revoked_at', 'operational', 'not_applicable', null, '§8.12.15: per-session revocation'],
            ['revoked_reason', 'operational', 'not_applicable', null, 'fixed vocabulary, never free text'],
            ['established_epoch', 'operational', 'not_applicable', null, '§8.12.11 combined epoch at establishment'],
        ]);

        DataClassification::annotate('reader_handoff_codes', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['project_id', 'operational', 'not_applicable', null, '🛑 §8.12.10: bound to the resolved project'],
            ['domain_id', 'operational', 'not_applicable', null, '🛑 §8.12.10: and to the verified domain row'],
            ['user_id', 'pseudonymous', 'platform', null, 'the dashboard principal'],
            ['code_hash', 'secret', 'not_applicable', null, '🛑 §9.1.4: CSPRNG, stored hashed'],
            ['code_hash_prefix', 'secret', 'not_applicable', null, 'indexed lookup prefix of the hash'],
            ['challenge', 'operational', 'not_applicable', null, '🛑 §8.12.18: S256 only, 43 base64url chars'],
            ['return_path', 'content', 'content', null, '🛑 a path, never a URL (§8.12.10)'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['expires_at', 'operational', 'not_applicable', null, '🛑 §8.12.10: within 30 seconds'],
            ['consumed_at', 'operational', 'not_applicable', null, '🛑 the single-use latch'],
        ]);

        DataClassification::annotate('grant_signing_keys', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['kid', 'operational', 'not_applicable', null, 'published in the JWKS'],
            ['state', 'operational', 'not_applicable', null, '🛑 §17: four-state rotation'],
            ['active_marker', 'derived', 'not_applicable', null, '🛑 exactly one active key'],
            ['public_key', 'operational', 'not_applicable', null, 'published; Ed25519 public key'],
            ['envelope_version', 'operational', 'not_applicable', null, '§9.1.7 envelope construction version'],
            ['kek_fingerprint', 'operational', 'not_applicable', null, 'which KEK wrapped this record'],
            ['wrapped_key', 'secret', 'not_applicable', 'credentials', '🛑 §9.1.7 data key, sealed under the KEK'],
            ['ciphertext', 'secret', 'not_applicable', 'credentials', '🛑 §8.12.11 grant signing key; mints read access'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
            ['activated_at', 'operational', 'not_applicable', null, null],
            ['retiring_at', 'operational', 'not_applicable', null, null],
            ['retired_at', 'operational', 'not_applicable', null, null],
        ]);
    }

    public function down(): void
    {
        DataClassification::forget('grant_signing_keys');
        DataClassification::forget('reader_handoff_codes');
        DataClassification::forget('docs_sessions');
        DataClassification::forget('reader_identities');
        DataClassification::forget('projects', ['identity_epoch']);

        Schema::dropIfExists('grant_signing_keys');
        Schema::dropIfExists('reader_handoff_codes');
        Schema::dropIfExists('docs_sessions');
        Schema::dropIfExists('reader_identities');

        Schema::table('projects', function (Blueprint $table): void {
            $table->dropColumn('identity_epoch');
        });
    }
};
