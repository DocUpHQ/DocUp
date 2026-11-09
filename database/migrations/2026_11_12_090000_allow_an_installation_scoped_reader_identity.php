<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 An installation-scoped binding could not provision a reader at all.
 *
 * Found in Phase 26b, because it is the first phase whose drivers have no other
 * scope available: §8.12.4 makes `ldap`, `mtls` and `header_trust`
 * **installation-scope only**. The defect is Phase 24's and it had been
 * unreachable until now.
 *
 * ## What was contradictory
 *
 * Three facts, each deliberate, which cannot all hold:
 *
 *  1. §8.12.3 scopes a binding at installation, organisation or project level,
 *     and `auth_provider_bindings.organisation_id` is **nullable** to say so.
 *     `provider_group_mappings.organisation_id` is nullable for the same
 *     reason.
 *  2. `App\Auth\Providers\Federation\ReaderProvisioning` writes
 *     `'organisation_id' => $binding->organisationId` — the **binding's**
 *     organisation and deliberately not the project's, with a comment saying
 *     "an installation-scoped binding has none, and the identity inherits
 *     that". `App\Models\ReaderIdentity`'s `#[Tenancy]` attribute says
 *     the same: "§8.12.3 scopes bindings at installation, organisation or
 *     project level and the identity inherits that organisation".
 *  3. `reader_identities.organisation_id` was `NOT NULL`.
 *
 * So the insert could not succeed. The failure arrived as
 * `TenancyContextMissing` from the `creating` hook in
 * `App\Concerns\BelongsToOrganisation` before the database ever saw it,
 * which is why it read as a tenancy-context mistake rather than as a schema
 * one — and the hook was fixed in the same commit to honour a deliberate null.
 *
 * ## 🛑 Why nullable rather than "the project's organisation"
 *
 * The alternative was considered and is worse. `reader_identities_subject_unique`
 * is `(binding_id, subject_hash)` — §8.12.1's key, with **no organisation in
 * it** — so one person behind an installation-scoped binding is one row. Keying
 * per organisation instead would give the same person N identities across N
 * organisations, which means a group removal has to reconcile N rows and
 * §8.12.1's stated key becomes a lie. Null is not an absent value here: it is
 * the statement "this reader was vouched for by the installation", which is
 * exactly what the binding's own null means.
 *
 * The global tenancy scope is untouched. An installation-scoped identity is
 * invisible to an organisation-scoped read, which is correct — every path that
 * needs it already spans all organisations deliberately
 * (`ReaderSessions::contextFor()`,
 * `App\Auth\Providers\Federation\ReaderProvisioning`), and those spans
 * carry their own notes saying why.
 *
 * 🛑 No classification change: the column's `organisational` classification and
 * its retention are what they were, and §8.22.7's check is on presence rather
 * than on nullability.
 */
return new class extends Migration
{
    public function up(): void
    {
        /*
         * 🛑 Raw DDL rather than `$table->uuidForeign(...)->nullable()->change()`.
         *
         * `change()` on a column carrying a foreign key makes Laravel drop and
         * recreate the key, and on MySQL 8.4 it reorders the index it rides on
         * — so the same column comes back with a different index name and
         * §9.1's index assertions start failing somewhere unrelated. The
         * `MODIFY` keeps the key and the index exactly as they are and changes
         * only the one thing this migration is about.
         */
        DB::statement('ALTER TABLE reader_identities MODIFY organisation_id BINARY(16) NULL');
    }

    public function down(): void
    {
        /*
         * 🛑 The rows have to go first, and they are deleted rather than
         * adopted. A reader identity with no organisation cannot be given one
         * — there is no correct answer, and picking a project's organisation
         * would mint the N-identities-per-person shape this migration exists to
         * avoid. Deleting them makes those readers sign in again, which costs
         * them one redirect; guessing would cost them somebody else's tenancy.
         */
        DB::table('reader_identities')->whereNull('organisation_id')->delete();

        DB::statement('ALTER TABLE reader_identities MODIFY organisation_id BINARY(16) NOT NULL');
    }
};
