<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * §8.12.18's SAML exchange — `oidc_authorisation_requests`' sibling.
 *
 * 🛑 **A second table rather than a shared one**, and the reason is the thing
 * each table is *for*. Phase 24's row holds a `state`, a `nonce` and a PKCE
 * verifier; a SAML exchange holds a request `ID` and a `RelayState` and no
 * verifier at all, because SAML has no PKCE. A shared table would be half its
 * columns NULL for every row, and a CHECK constraint explaining which half —
 * which is the shape a table takes when two things were merged for tidiness
 * rather than because they are one thing.
 *
 * What they *do* share is the reasoning, and it is worth restating because it
 * is the argument against the obvious alternative. The dashboard session was
 * rejected for Phase 24 because it cannot express single-use, has no replay
 * latch and leaves the audit chain nothing to name — and every word of that
 * holds here, with one addition: §8.12.18 requires `InResponseTo` verified, so
 * DocUp must remember a request id it sent. A session holds one per key, so two
 * tabs would clobber each other's request and the second login would present an
 * `InResponseTo` the first had overwritten.
 *
 * 🛑 **Proposed §10.6 addition**, like its sibling. §10.6 names
 * `provider_group_mappings` and the policy tables; it names no in-flight
 * authentication state for either protocol.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('saml_auth_requests', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');

            /*
             * 🛑 `restrictOnDelete`, as Phase 24's does: §8.12.19 forbids
             * deleting a referenced binding, and an in-flight exchange is a
             * reference. A cascade would let an operator delete a binding
             * mid-login and leave the ACS with nothing to judge against — which
             * is indistinguishable from a forged `RelayState`.
             */
            $table->uuidForeign('binding_id');

            /*
             * Where the reader came from and where they are going back to.
             * §8.12.10: the return URL comes "from the verified domain row,
             * never from a request parameter" — so the domain lives here and
             * the ACS reads it from the row, never from `RelayState`.
             */
            $table->uuidForeign('domain_id');
            $table->uuidForeign('project_id', index: false);

            /*
             * 🛑 The `<AuthnRequest>` `ID`, in **plaintext**, and §9.1.4 is why
             * it is not hashed.
             *
             * That rule governs *security tokens* — "CSPRNG, stored hashed, and
             * never UUIDv7" — and the request id is not one. It travels in a
             * query string the reader's own browser carries, the identity
             * provider echoes it back in a response the same browser carries,
             * and knowing it buys an attacker nothing: `InResponseTo` is checked
             * only after both signatures verify, so forging one requires the
             * provider's private key, not this value. `RelayState` below is the
             * security token in this exchange, and it is hashed.
             *
             * 🛑 And the plaintext is **needed**, which settles it. The
             * comparison is `hash_equals(expected, presented)` inside
             * `ResponseValidator`, which has to be handed the id DocUp sent.
             * Hashing it here would mean either passing a digest into a
             * validator that has no business knowing how this table stores
             * things, or a second comparison path — a worse shape bought with
             * no security.
             *
             * 🛑 Named `in_response_to` rather than `request_id`, and §9.1.1 is
             * why. That rule makes every column named `*_id` a `BINARY(16)`
             * UUIDv7 and CI enforces it — which it should, because the one place
             * an identifier column quietly becomes a string is the place a join
             * silently stops working. This value is not a DocUp identifier at
             * all: it is the string a response's `InResponseTo` attribute must
             * equal. Naming it after the attribute it is compared against says
             * so, and stops the column claiming to be something it is not.
             *
             * Unique, so an `InResponseTo` can never name two exchanges.
             */
            $table->string('in_response_to', 64)->collation('ascii_bin');

            /*
             * 🛑 `RelayState`, hashed, and it is the lookup key.
             *
             * SAML's equivalent of OIDC's `state`: the Web Browser SSO Profile
             * requires the identity provider to return it unmodified, which
             * ADR 0013 measured. Stored hashed for the same reason
             * `oidc_authorisation_requests.state_hash` is — §9.1.4 — with the
             * indexed prefix `tokenHash()` writes beside it.
             */
            $table->tokenHash('relay_state_hash');

            /*
             * §8.12.10's challenge, carried through so the ACS can mint a
             * handoff code the documentation origin will accept. 43 base64url
             * characters, the shape `reader_handoff_codes` stores.
             */
            $table->char('handoff_challenge', 43)->collation('ascii_bin');

            /* Normalised by `ReaderHandoff::safeReturnPath()` before storage. */
            $table->string('return_path', 512);

            $table->datetime('expires_at', 3);
            $table->datetime('consumed_at', 3)->nullable();
            $table->unsignedTinyInteger('attempts')->default(0);

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique('relay_state_hash', 'saml_auth_requests_relay_unique');
            $table->unique('in_response_to', 'saml_auth_requests_in_response_to_unique');
            $table->index('expires_at', 'saml_auth_requests_expiry_index');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('binding_id')->references('id')->on('auth_provider_bindings')->restrictOnDelete();
            $table->foreign('domain_id')->references('id')->on('domains')->cascadeOnDelete();
            $table->foreign('project_id')->references('id')->on('projects')->cascadeOnDelete();
        });

        DataClassification::annotate('saml_auth_requests', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['binding_id', 'operational', 'not_applicable', null, '🛑 §8.12.19: RESTRICT, not cascade'],
            ['domain_id', 'operational', 'not_applicable', null, '🛑 §8.12.10: the return address, server-side'],
            ['project_id', 'operational', 'not_applicable', null, null],
            ['in_response_to', 'operational', 'not_applicable', null, '🛑 §8.12.18: what InResponseTo must match; not an identifier (§9.1.1)'],
            ['relay_state_hash', 'secret', 'not_applicable', null, '🛑 §9.1.4: CSPRNG, stored hashed'],
            ['relay_state_hash_prefix', 'secret', 'not_applicable', null, 'the lookup prefix'],
            ['handoff_challenge', 'secret', 'not_applicable', null, "§8.12.10's challenge, carried through"],
            ['return_path', 'content', 'content', null, 'normalised before storage, never replayed raw'],
            ['expires_at', 'operational', 'not_applicable', null, 'short; an auth request is not durable'],
            ['consumed_at', 'operational', 'not_applicable', null, '🛑 §8.12.18: the single-use latch'],
            ['attempts', 'operational', 'not_applicable', null, 'bounded, like the handoff code'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);
    }

    public function down(): void
    {
        DataClassification::forget('saml_auth_requests');

        Schema::dropIfExists('saml_auth_requests');
    }
};
