<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Repositories, their credentials, and the component sources that attach one
 * repository to many projects (§8.3, §10.2).
 *
 * 🛑 `component_sources` is created **here** rather than in Phase 13, and
 * §10.2 says why: "`component_sources` is deliberately absent: it carries a
 * foreign key to `repositories`, which arrives with source connection in a
 * later phase." This is that phase. It is also what makes Phase 05's exit
 * criterion — one repository connected once and attached to two projects —
 * expressible at all: attachment runs repository → component_source →
 * component → mount → version → project, and without the first hop there is
 * nothing to attach.
 *
 * 🛑 The uniqueness constraint is **not** §10.2's as originally written. ADR
 * 0009 found three defects in `UNIQUE (provider, provider_repo_id)` while
 * verifying §18.27, and the specification is amended in place:
 *
 *  - The identifier is unique **per instance**, not per provider. Gitea and
 *    Forgejo are self-hosted only; repository 42 exists on every Gitea server
 *    in the world, so the provider **host** must be in the key.
 *  - The key was not tenant-scoped. Two organisations on one installation may
 *    legitimately connect the same public GitHub repository; a global key
 *    would let the first to attach it deny it to the rest, and would leak the
 *    collision across the tenant boundary.
 *  - `provider_repo_id` is nullable, because §8.3.8 requires degrading to
 *    normalised-URL matching "where none exists" — a bare SSH remote, or a
 *    provider whose identifier turns out to be mutable after all.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('repository_credentials', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');

            // §8.3.3's four kinds. Stored rather than derived from the payload
            // shape, because the AAD binds to it (see EnvelopeCipher::aad) and
            // an AAD component that is computed can disagree with itself.
            $table->enum('kind', ['github_app', 'oauth', 'pat', 'deploy_key']);

            $table->enum('provider', [
                'github', 'gitlab', 'bitbucket_cloud', 'bitbucket_server', 'gitea', 'forgejo', 'generic',
            ]);

            /*
             * The instance this credential is good for. ASCII-collated per
             * §9.1.6: a hostname comparison that is case- or accent-insensitive
             * is a hostname comparison that can be made to match the wrong host.
             */
            $table->string('provider_host', 253)->charset('ascii')->collation('ascii_bin');

            // Shown in the UI. Never the credential, and never derived from it.
            $table->string('display_name', 190);

            /*
             * ------------------------------------------------- §9.1.7 envelope
             *
             * Three columns, not one, and the split is the point: rotating the
             * KEK rewrites `wrapped_key` alone and never reads `ciphertext`.
             * That is what makes "installation_security_admin may rotate but
             * never read" a property of the code rather than a promise.
             */
            $table->unsignedSmallInteger('envelope_version');
            $table->string('kek_fingerprint', 32);
            $table->binary('wrapped_key', 255, false);
            $table->binary('ciphertext', 4096, false);

            /*
             * The public half of a deploy key. 🛑 Outside the envelope on
             * purpose: the operator must read it to install it at the
             * provider, and a UI that had to unseal a credential to display a
             * public key would be a UI with an unseal path §8.3.3 does not
             * want it to have.
             */
            $table->text('public_material')->nullable();

            $table->datetime('expires_at', 3)->nullable();
            $table->datetime('last_used_at', 3)->nullable();
            $table->datetime('rotated_at', 3)->nullable();

            $table->enum('state', ['active', 'expired', 'revoked'])->default('active');

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->index(['organisation_id', 'provider', 'state']);
            $table->index('kek_fingerprint');   // finds the records a rotation has not reached

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
        });

        Schema::create('repositories', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');

            $table->enum('provider', [
                'github', 'gitlab', 'bitbucket_cloud', 'bitbucket_server', 'gitea', 'forgejo', 'generic',
            ]);

            $table->string('provider_host', 253)->charset('ascii')->collation('ascii_bin');
            $table->binary('provider_host_hash', 20, true)->storedAs('UNHEX(SHA1(provider_host))');

            /*
             * 🛑 The §18.27 identifier, canonicalised by
             * `App\Source\IdentifierShape` before it ever reaches this column.
             * Stored as text because the five providers disagree on the type:
             * four issue an int64 and Bitbucket Cloud issues a braced,
             * case-insensitive UUID. An uncanonicalised VARCHAR would hold
             * `{A1B2…}` and `a1b2…` as two rows for one repository, which is a
             * uniqueness constraint that does not constrain.
             */
            $table->string('provider_repo_id', 191)->nullable();

            /*
             * §8.3.8's fallback key, and the only key for a generic remote.
             * Scheme-independent, so the https and ssh forms of one repository
             * are one row. 1024 bytes exceeds InnoDB's index prefix, hence the
             * §9.1.5 companion hash.
             */
            $table->string('normalised_url', 1024);
            $table->binary('normalised_url_hash', 32, true)->storedAs('UNHEX(SHA2(normalised_url, 256))');

            // What the operator typed, after §8.3.4 validation. Kept so a
            // rename can be reported as a change rather than a replacement.
            $table->string('clone_url', 1024);
            $table->string('default_branch', 255)->nullable();

            /*
             * 🛑 §8.3.5: submodules are cloned non-recursively and **only on
             * explicit per-repository opt-in** (CVE-2025-48384,
             * CVE-2023-22490). Default false. There is deliberately no
             * `submodules_recursive` column: recursion is not a setting with a
             * safe default, it is a capability DocUp does not have.
             */
            $table->boolean('submodules_enabled')->default(false);

            $table->uuidForeign('credential_id', nullable: true);

            /*
             * §8.3.6: "A repository connected but unprovisioned MUST be
             * reported as such in the UI rather than silently never building."
             * The state is stored rather than inferred from the absence of a
             * webhook row, because "we never tried" and "we tried and the
             * credential could not" need different words in front of an
             * operator.
             */
            $table->enum('webhook_state', ['unprovisioned', 'provisioned', 'manual_required', 'failed'])
                ->default('unprovisioned');
            $table->datetime('webhook_checked_at', 3)->nullable();

            $table->enum('state', ['active', 'paused', 'unreachable', 'archived'])->default('active');

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();
            $table->datetime('deleted_at', 3)->nullable()->index();

            /*
             * 🛑 ADR 0009, amending §10.2. Tenant, provider, **instance** and
             * identifier. MySQL permits unlimited NULLs in a unique index, so
             * this constrains exactly the rows that have a stable identifier
             * and leaves the §8.3.8 fallback to the index below — the §18.21
             * idiom, verified on 8.4.11 in Phase 03.
             */
            $table->unique(
                ['organisation_id', 'provider', 'provider_host_hash', 'provider_repo_id'],
                'repositories_provider_identity_unique',
            );

            // The fallback key, and the reason §8.3.2's "connected once" holds
            // even for a provider that supplies no identifier.
            $table->unique(['organisation_id', 'normalised_url_hash'], 'repositories_normalised_url_unique');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('credential_id')->references('id')->on('repository_credentials')->nullOnDelete();
        });

        Schema::create('component_sources', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('component_id');
            $table->uuidForeign('repository_id');

            /*
             * 🛑 §8.4.1: configuration discovery runs relative to this path,
             * not to the repository root. A monorepo contributing three
             * components holds three configuration files at three paths, and
             * rooting discovery would make the one-repository-to-many-
             * components case — the whole reason the component model exists —
             * unexpressible.
             */
            $table->string('source_path', 255)->default('');
            $table->binary('source_path_hash', 20, true)->storedAs('UNHEX(SHA1(source_path))');

            $table->string('module', 64)->default('');      // distributed-component namespace [P2]
            $table->unsignedSmallInteger('priority')->default(100);

            $table->json('path_filters')->nullable();
            $table->json('ref_include_patterns')->nullable();
            $table->json('ref_exclude_patterns')->nullable();

            $table->enum('version_label_strategy', ['ref_name', 'semver_from_tag', 'regex'])->default('ref_name');
            $table->string('version_label_regex', 255)->nullable();

            $table->enum('state', ['active', 'orphaned', 'retired'])->default('active');

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();
            $table->datetime('deleted_at', 3)->nullable()->index();

            // §10.2 verbatim: one source per (repository, path, module).
            $table->unique(['repository_id', 'source_path_hash', 'module'], 'component_sources_unique');
            $table->index(['component_id', 'state']);

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('component_id')->references('id')->on('components')->cascadeOnDelete();
            $table->foreign('repository_id')->references('id')->on('repositories')->cascadeOnDelete();
        });

        DataClassification::annotate('repository_credentials', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['kind', 'operational', 'not_applicable', null, '§8.3.3 credential kinds'],
            ['provider', 'operational', 'not_applicable', null, null],
            ['provider_host', 'operational', 'not_applicable', null, 'the instance this credential is good for'],
            ['display_name', 'operational', 'not_applicable', null, 'operator-chosen label; never the credential'],
            ['envelope_version', 'operational', 'not_applicable', null, '§9.1.7 envelope construction version'],
            ['kek_fingerprint', 'operational', 'not_applicable', null, 'which KEK wrapped this record; reveals nothing about it'],
            ['wrapped_key', 'secret', 'not_applicable', 'credentials', '🛑 §9.1.7 data key, sealed under the KEK; rotation rewrites only this'],
            ['ciphertext', 'secret', 'not_applicable', 'credentials', '🛑 §9.1.7 sealed payload; never exported, never logged, never in an API response (§8.3.3)'],
            ['public_material', 'operational', 'not_applicable', null, 'deploy-key public half; not secret, and the operator must read it'],
            ['expires_at', 'operational', 'not_applicable', null, null],
            ['last_used_at', 'operational', 'not_applicable', null, null],
            ['rotated_at', 'operational', 'not_applicable', null, '§9.1.7 KEK rotation'],
            ['state', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('repositories', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['provider', 'operational', 'not_applicable', null, '§8.3.1'],
            ['provider_host', 'operational', 'not_applicable', null, 'ascii_bin; §9.1.6'],
            ['provider_host_hash', 'derived', 'not_applicable', null, '§9.1.5 companion hash for the identity index'],
            ['provider_repo_id', 'operational', 'not_applicable', null, '🛑 §18.27 stable identifier, canonicalised (ADR 0009)'],
            ['normalised_url', 'operational', 'not_applicable', null, '§8.3.8 fallback matching key'],
            ['normalised_url_hash', 'derived', 'not_applicable', null, '§9.1.5 companion hash'],
            ['clone_url', 'operational', 'not_applicable', null, 'as supplied, after §8.3.4 validation; never carries a credential'],
            ['default_branch', 'operational', 'not_applicable', null, null],
            ['submodules_enabled', 'operational', 'not_applicable', null, '🛑 §8.3.5 per-repository opt-in, non-recursive'],
            ['credential_id', 'operational', 'not_applicable', null, null],
            ['webhook_state', 'operational', 'not_applicable', null, '§8.3.6 unprovisioned must be visible'],
            ['webhook_checked_at', 'operational', 'not_applicable', null, null],
            ['state', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
            ['deleted_at', 'operational', 'not_applicable', null, '§8.22.6 recovery window'],
        ]);

        DataClassification::annotate('component_sources', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['component_id', 'operational', 'not_applicable', null, null],
            ['repository_id', 'operational', 'not_applicable', null, '§8.3.2 one repository, many components'],
            ['source_path', 'operational', 'not_applicable', null, '🛑 §8.4.1 configuration discovery is relative to this'],
            ['source_path_hash', 'derived', 'not_applicable', null, '§9.1.5 companion hash'],
            ['module', 'operational', 'not_applicable', null, 'distributed-component namespace [P2]'],
            ['priority', 'operational', 'not_applicable', null, '§8.7.14 collision ordering'],
            ['path_filters', 'operational', 'not_applicable', null, '§18.15 rebuild gating globs'],
            ['ref_include_patterns', 'operational', 'not_applicable', null, null],
            ['ref_exclude_patterns', 'operational', 'not_applicable', null, null],
            ['version_label_strategy', 'operational', 'not_applicable', null, null],
            ['version_label_regex', 'operational', 'not_applicable', null, null],
            ['state', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
            ['deleted_at', 'operational', 'not_applicable', null, '§8.22.6 recovery window'],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('component_sources');
        Schema::dropIfExists('repositories');
        Schema::dropIfExists('repository_credentials');

        foreach (['component_sources', 'repositories', 'repository_credentials'] as $table) {
            DataClassification::forget($table);
        }
    }
};
