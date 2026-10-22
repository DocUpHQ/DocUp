<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Serving hostnames (§8.10, §10.5).
 *
 * 🛑 Created in **Phase 04**, with its full column set and no behaviour. §17 is
 * explicit: "the `domains` and `domain_mounts` tables with their full §10.5
 * column set (rows only — no claims, verification, tombstones or certificates,
 * which are P18's), because the grammar's first step matches on
 * `domain_mounts.path_prefix` and a resolver frozen without that column is
 * frozen around a hole".
 *
 * So the state machine's columns exist and nothing drives them yet. That is
 * deliberate and it is the opposite of speculative: the resolver is frozen at
 * the end of this phase, and it reads `state` to decide whether a host may be
 * served at all (§8.10.6: "Suspended and unverified hosts MUST be neither served
 * nor certified"). A column added afterwards would mean unfreezing the resolver.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('domains', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');

            /*
             * 253 bytes is the maximum length of a DNS name, so a longer value
             * is not a hostname. ASCII collation because a hostname reaching
             * this column is already punycode (§8.10's normalisation is P18's,
             * and this column is where its output lands): comparing A-labels
             * under utf8mb4 would make `Example.com` and `example.com` distinct
             * rows under a case-sensitive collation and identical under a
             * case-insensitive one, neither of which is a decision to leave to
             * a default.
             */
            $table->string('host', 253)->collation('ascii_bin');

            /*
             * Which of §8.9.3's resolution steps this host answers at. The
             * resolver tries exact custom domain → single-label default
             * subdomain → preview host, and it has to know which kind a row is
             * to apply the right matching rule: a preview host is split on the
             * **last** `--`, and a default subdomain is a single label under
             * the documentation apex. Deriving the kind from the string at
             * request time would put that classification on the hot path and in
             * two places.
             */
            $table->enum('kind', ['default_subdomain', 'custom', 'apex', 'preview'])->default('custom');

            /*
             * 🛑 §8.10.6's state machine: "State MUST progress
             * `verified → active → failing` (7-day grace, warning at the first
             * failure, not the twenty-ninth) `→ suspended`." `pending` is the
             * state before any proof, which §8.10.4 requires to precede "any
             * certificate issuance or any byte served for a custom hostname".
             */
            $table->enum('state', ['pending', 'verified', 'active', 'failing', 'suspended'])
                ->default('pending');

            // §8.10.4's three complementary mechanisms. Null until proven.
            $table->enum('verification_method', ['parent_claim', 'dns_txt', 'cname'])->nullable();

            $table->datetime('verified_at', 3)->nullable();
            $table->datetime('last_checked_at', 3)->nullable();

            // §8.10.6's grace window starts here: "warning at the first
            // failure", and suspension seven days after it.
            $table->datetime('failing_since', 3)->nullable();
            $table->datetime('suspended_at', 3)->nullable();

            /*
             * 🛑 §8.10.5: "Global hostname uniqueness MUST apply **only** among
             * proven claims, via a `STORED` generated column that is NULL for
             * unverified rows and carries the unique index. An unconditional
             * unique index lets a squatter's pending row block the legitimate
             * owner."
             *
             * This is the §18.21 idiom, verified on MySQL 8.4.11 in Phase 03: a
             * UNIQUE index over a STORED generated column yielding NULL permits
             * unlimited NULLs and rejects the second non-NULL. So any number of
             * organisations may have a pending claim on one hostname, and
             * exactly one may have a proven one.
             *
             * Keyed on `verified_at` rather than on `state`, deliberately: a
             * suspended host was proven once, and releasing its uniqueness the
             * moment it was suspended would let a squatter take it during the
             * 90-day tombstone window §8.10 reserves for the original owner.
             */
            $table->string('claimed_host', 253)
                ->collation('ascii_bin')
                ->nullable()
                ->storedAs('IF(`verified_at` IS NULL, NULL, `host`)');

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique('claimed_host', 'domains_claimed_host_unique');

            // Not unique: an unproven row may duplicate a hostname, which is
            // the whole point of the generated column above. Indexed because
            // the resolver looks a host up by exactly this column.
            $table->index(['host', 'state'], 'domains_host_state_index');
            $table->index(['organisation_id', 'state']);

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
        });

        DataClassification::annotate('domains', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['host', 'operational', 'not_applicable', null, 'a serving hostname; public by nature'],
            ['kind', 'operational', 'not_applicable', null, "§8.9.3's resolution step"],
            ['state', 'operational', 'not_applicable', null, '§8.10.6 state machine'],
            ['verification_method', 'operational', 'not_applicable', null, '§8.10.4'],
            ['verified_at', 'operational', 'not_applicable', null, 'proof precedes service (§8.10.4)'],
            ['last_checked_at', 'operational', 'not_applicable', null, '§8.10.6 daily re-verification'],
            ['failing_since', 'operational', 'not_applicable', null, '§8.10.6 seven-day grace'],
            ['suspended_at', 'operational', 'not_applicable', null, null],
            ['claimed_host', 'derived', 'not_applicable', null, '🛑 §8.10.5 proven-claims-only uniqueness'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('domains');
        DataClassification::forget('domains');
    }
};
