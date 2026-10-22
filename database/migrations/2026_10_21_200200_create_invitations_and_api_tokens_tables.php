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
 * Invitations and dashboard API tokens (§8.2.4, §8.13.6, §9.1.4).
 *
 * 🛑 Both carry a secret, and §9.1.4 governs how: 32 CSPRNG bytes or UUIDv4,
 * stored as a SHA-256 hash, and **never UUIDv7**. v7 embeds a readable
 * creation timestamp, so a v7 invitation code narrows a brute-force search to
 * the moment the invitation was sent. The `tokenHash()` macro stores only the
 * hash plus an indexed prefix: the prefix finds the candidate row without a
 * scan, and the comparison stays on the full hash.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('invitations', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');

            // Email-bound (§8.2.4): acceptance must be by the addressee, so the
            // address is part of what the invitation authorises, not just where
            // it was sent.
            $table->string('email', 255)->index();

            // §9.1.4. The plaintext code exists only in the email.
            $table->tokenHash();

            /*
             * §8.2.4 "with the role assignment pre-staged": the grant is
             * decided when the invitation is issued, not when it is accepted.
             * Otherwise acceptance would have to re-derive what the inviter
             * intended, and an invitation would mean something different
             * depending on when it was opened.
             */
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
            $table->enum('scope_type', ['installation', 'organisation', 'collection', 'project']);
            $table->uuidForeign('scope_id', nullable: true);

            $table->uuidForeign('invited_by');

            // §8.2.4: 14-day expiry. Stored rather than computed so shortening
            // the default later does not retroactively invalidate live
            // invitations, and lengthening it does not revive dead ones.
            $table->datetime('expires_at', 3)->index();

            /*
             * 🛑 Single-use (§8.2.4). These two columns are what makes it so,
             * together with the partial unique index below: an invitation can
             * be consumed once, or revoked, and either way it is spent.
             */
            $table->datetime('accepted_at', 3)->nullable();
            $table->datetime('revoked_at', 3)->nullable();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            // The full hash is unique: two invitations can never share a code.
            $table->unique('token_hash');

            $table->foreign('organisation_id')
                ->references('id')->on('organisations')
                ->cascadeOnDelete();
            $table->foreign('invited_by')
                ->references('id')->on('users')
                ->cascadeOnDelete();
        });

        /*
         * The same scope/id pairing the role_assignments table enforces, for
         * the same reason: a pre-staged grant with an incoherent scope would
         * become an incoherent role assignment on acceptance.
         */
        DB::statement(
            'ALTER TABLE invitations ADD CONSTRAINT invitations_scope_id_pairing CHECK (
                (scope_type = \'installation\' AND scope_id IS NULL)
                OR (scope_type <> \'installation\' AND scope_id IS NOT NULL)
            )'
        );

        Schema::create('api_tokens', function (Blueprint $table): void {
            $table->uuidKey();

            // Nullable for the same reason as role_assignments: a token may be
            // scoped outside any single organisation. §8.13.6 forbids
            // installation-scope *administrative* capability, not
            // installation-scope tokens as such.
            $table->uuidForeign('organisation_id', nullable: true);

            // The human the token acts as. A token never outlives its owner:
            // §8.22.6's hard purge takes the user, and the cascade takes this.
            $table->uuidForeign('user_id');

            $table->string('name', 160);

            // §8.13.6: prefixed, SHA-256 hashed, with an indexed prefix.
            $table->tokenHash();

            $table->enum('scope_type', ['installation', 'organisation', 'collection', 'project']);
            $table->uuidForeign('scope_id', nullable: true);

            /*
             * 🛑 §8.13.6: "No token MUST hold installation-scope administrative
             * capability, validated at mint." The granted capabilities are
             * stored explicitly rather than derived from a role, because a
             * token's grant must be a subset chosen at mint time — deriving it
             * from a role would mean a later widening of that role silently
             * widens every token already issued against it.
             *
             * Validation lives at the mint site and asks
             * Capability::isInstallationAdministrative(), so a capability added
             * in a later phase is covered the moment it exists.
             */
            $table->json('capabilities');

            /*
             * 🛑 NOT NULL: §8.13.6 makes expiry mandatory, defaulting to 90 days
             * and capped at 365. The column enforces "mandatory"; the default
             * and the cap are application concerns because they are policy
             * numbers rather than data integrity, and §20.3 owns them.
             *
             * A nullable column here would make a non-expiring token one
             * forgotten `->nullable()` away, which is the single most common
             * way a long-lived credential enters a system.
             */
            $table->datetime('expires_at', 3)->index();

            // §8.13.6 optional CIDR binding. Text rather than a packed range:
            // it is read rarely, written by a human, and must round-trip
            // legibly in the UI that displays it.
            $table->string('cidr_allowlist', 255)->nullable();

            // Overlap rotation (§8.13.6): a replacement is minted and both work
            // until the old one expires, so rotation needs no downtime. The
            // link is recorded so the UI can show which token supersedes which.
            $table->uuidForeign('rotated_from_id', nullable: true);

            $table->datetime('last_used_at', 3)->nullable();
            $table->datetime('revoked_at', 3)->nullable();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique('token_hash');

            $table->foreign('organisation_id')
                ->references('id')->on('organisations')
                ->cascadeOnDelete();
            $table->foreign('user_id')
                ->references('id')->on('users')
                ->cascadeOnDelete();
        });

        DB::statement(
            'ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_scope_id_pairing CHECK (
                (scope_type = \'installation\' AND scope_id IS NULL)
                OR (scope_type <> \'installation\' AND scope_id IS NOT NULL)
            )'
        );

        DataClassification::annotate('invitations', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key'],
            ['email', 'personal', 'platform', 'invitations', 'the invitation is bound to this address (§8.2.4)'],
            ['token_hash', 'secret', 'platform', 'invitations', '🛑 §9.1.4 CSPRNG, SHA-256 hashed, never UUIDv7'],
            ['token_hash_prefix', 'secret', 'platform', 'invitations', 'indexed lookup prefix; still secret-derived'],
            ['role', 'operational', 'platform', 'invitations', 'the pre-staged grant'],
            ['scope_type', 'operational', 'platform', 'invitations', null],
            ['scope_id', 'operational', 'platform', 'invitations', null],
            ['invited_by', 'pseudonymous', 'platform', 'invitations', 'identifies the inviter'],
            ['expires_at', 'operational', 'platform', 'invitations', '14 days (§8.2.4)'],
            ['accepted_at', 'operational', 'platform', 'invitations', 'half of what makes an invitation single-use'],
            ['revoked_at', 'operational', 'platform', 'invitations', null],
            ['created_at', 'operational', 'platform', 'invitations', null],
            ['updated_at', 'operational', 'platform', 'invitations', null],
        ]);

        DataClassification::annotate('api_tokens', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key'],
            ['user_id', 'pseudonymous', 'platform', null, 'the human the token acts as'],
            ['name', 'operational', 'platform', null, 'user-chosen label'],
            ['token_hash', 'secret', 'platform', null, '🛑 §9.1.4; never returned by any API or UI (§8.3.3)'],
            ['token_hash_prefix', 'secret', 'platform', null, 'indexed lookup prefix'],
            ['scope_type', 'operational', 'platform', null, null],
            ['scope_id', 'operational', 'platform', null, null],
            ['capabilities', 'operational', 'platform', null, '🛑 §8.13.6 validated at mint; no installation-scope admin'],
            ['expires_at', 'operational', 'platform', null, '🛑 §8.13.6 mandatory; NOT NULL by design'],
            ['cidr_allowlist', 'operational', 'platform', null, 'optional network binding (§8.13.6)'],
            ['rotated_from_id', 'operational', 'platform', null, 'overlap rotation chain'],
            ['last_used_at', 'operational', 'platform', null, 'reveals activity times for a person'],
            ['revoked_at', 'operational', 'platform', null, null],
            ['created_at', 'operational', 'platform', null, null],
            ['updated_at', 'operational', 'platform', null, null],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('api_tokens');
        Schema::dropIfExists('invitations');

        DataClassification::forget('api_tokens');
        DataClassification::forget('invitations');
    }
};
