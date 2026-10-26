<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * §8.10.10–§8.10.17's certificate sources, budgets and attempts (§10.5).
 *
 * Phase 18 proved hostnames. This is what a proven hostname buys: a
 * certificate. The four tables are §10.5's last four hosting tables, and the
 * `domains` columns added at the end are the per-host state the serving path
 * and the prober read.
 *
 * 🛑 Two idioms are carried over deliberately rather than reinvented.
 *
 * The **STORED generated column under a unique index** — §8.10.5's shape, now
 * applied to `certificates.active_host`. A host has at most one active
 * certificate and any number of superseded ones, which is the same "many
 * NULLs, one value" constraint, and expressing it in the database means a
 * double activation is an error rather than a second certificate that half
 * the handshakes see.
 *
 * The **envelope columns** of §9.1.7 — `envelope_version`, `kek_fingerprint`,
 * `wrapped_key`, `ciphertext` — because §8.10.15 asks for exactly what
 * `App\Credentials\EnvelopeCipher` already does: "All certificate private keys
 * and ACME account keys MUST be stored with authenticated encryption". A
 * second encryption scheme for key material would be a second place to get
 * AEAD wrong.
 */
return new class extends Migration
{
    public function up(): void
    {
        /*
         * §8.10.14's ACME identity, for both the public directory and an
         * internal one (step-ca, Vault, ADCS).
         *
         * 🛑 Installation-scoped, not organisation-scoped. An ACME account is
         * the installation's relationship with a CA — Let's Encrypt's
         * per-registered-domain ceiling is global across accounts anyway
         * (§8.10.10), so an account per tenant would buy nothing and multiply
         * the key material §8.10.15 has to protect.
         */
        Schema::create('acme_accounts', function (Blueprint $table): void {
            $table->uuidKey();

            /*
             * The name configuration refers to this account by. Unique,
             * because `config/tls.php` names a source's account by label and
             * two accounts with one label is a configuration whose meaning
             * depends on insertion order.
             */
            $table->string('label', 64);

            $table->enum('kind', ['public', 'internal']);

            /*
             * The ACME directory. 512 rather than 253: this is a URL, and an
             * internal directory commonly carries a provisioner path —
             * step-ca's is `/acme/<provisioner>/directory`.
             */
            $table->string('directory_url', 512);

            /*
             * 🛑 §18.20's consequence column, applied: "P19 … requires an
             * operator-supplied ACME account". The contact is the address the
             * CA sends expiry and policy mail to, and an installation that
             * never supplied one finds out about a revocation from its
             * readers.
             */
            $table->string('contact', 255)->nullable();

            // The `kid` the CA issued. NULL until registration succeeds.
            $table->string('account_url', 512)->nullable();

            /*
             * 🛑 §8.10.15. The account key signs every JWS this installation
             * sends to the CA; whoever holds it can revoke every certificate
             * the account ever issued. Sealed exactly as a repository
             * credential is, by the same cipher, for the same reason.
             */
            $table->unsignedSmallInteger('envelope_version');
            $table->string('kek_fingerprint', 32);
            $table->binary('wrapped_key', 255, false);
            $table->binary('ciphertext', 4096, false);

            $table->enum('state', ['pending', 'registered', 'disabled'])->default('pending');

            $table->datetime('registered_at', 3)->nullable();
            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique('label', 'acme_accounts_label_unique');
            $table->index('kek_fingerprint');   // the records a KEK rotation has not reached
        });

        /*
         * §8.10.14's four sources, one table. What differs between them is
         * where the bytes came from, which is one column.
         */
        Schema::create('certificates', function (Blueprint $table): void {
            $table->uuidKey();

            $table->string('host', 253)->collation('ascii_bin');

            /*
             * 🛑 §8.10.5's idiom, one table along. NULL unless the row is the
             * active one, so a host may accumulate any number of superseded
             * and revoked certificates and carry exactly one that the
             * handshake will serve.
             *
             * Without it, "which certificate does this host present?" is a
             * query with an implicit assumption, and the day two rows are
             * active the answer depends on the plan the optimiser picked.
             */
            $table->string('active_host', 253)
                ->collation('ascii_bin')
                ->nullable()
                ->storedAs("IF(`state` = 'active', `host`, NULL)");

            $table->enum('source', ['public_acme', 'internal_acme', 'uploaded', 'development']);
            $table->enum('state', ['active', 'superseded', 'revoked'])->default('active');

            /*
             * Nullable because the installation's own §8.10.10 wildcard
             * belongs to no tenant and no single hostname row, and because an
             * operator may upload a certificate before the domain is attached.
             * `nullOnDelete` so releasing a domain does not destroy the
             * evidence of what it was served with.
             */
            $table->uuidForeign('organisation_id', nullable: true);
            $table->uuidForeign('domain_id', nullable: true);
            $table->uuidForeign('acme_account_id', nullable: true);

            /*
             * The leaf and its intermediates, PEM, in the order a TLS
             * handshake wants them. Public by construction — this is what the
             * server sends every client — so it is stored in the clear and
             * `MEDIUMTEXT` because a chain with two intermediates and a
             * 4096-bit key runs past `TEXT`'s 64 KiB only in pathological
             * cases but a cross-signed chain is not pathological.
             */
            $table->mediumText('chain_pem');

            // 🛑 §8.10.15 again: the private key, sealed.
            $table->unsignedSmallInteger('envelope_version');
            $table->string('kek_fingerprint', 32);
            $table->binary('wrapped_key', 255, false);
            $table->binary('ciphertext', 8192, false);

            /*
             * What the prober compares against. Recorded at store time from
             * the certificate itself rather than from the issuer's response,
             * so a source that lies about what it issued is caught by the
             * first probe instead of at expiry.
             */
            $table->string('serial', 64);
            $table->string('issuer', 255);
            $table->string('fingerprint', 64);     // sha256 of the DER leaf, hex
            $table->datetime('not_before', 3);
            $table->datetime('not_after', 3);

            $table->datetime('activated_at', 3)->nullable();
            $table->datetime('superseded_at', 3)->nullable();
            $table->datetime('revoked_at', 3)->nullable();
            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique('active_host', 'certificates_active_host_unique');
            $table->index(['host', 'state']);
            $table->index('not_after');            // the renewal sweep
            $table->index('kek_fingerprint');

            $table->foreign('organisation_id')->references('id')->on('organisations')->nullOnDelete();
            $table->foreign('domain_id')->references('id')->on('domains')->nullOnDelete();
            $table->foreign('acme_account_id')->references('id')->on('acme_accounts')->nullOnDelete();
        });

        /*
         * §8.10.13's attempts table, and §8.10.17's only observability.
         *
         * 🛑 A **denied permission query writes nothing.** The requirement
         * records attempts, and Phase 19's exit criterion is "500 bogus SNI
         * handshakes per minute trigger zero ACME attempts" — a row per
         * handshake would turn an unauthenticated handshake into an
         * unauthenticated INSERT, which is the amplification the permission
         * endpoint exists to prevent. What lands here is an attempt that was
         * **permitted** (rare, rate-limited, and the thing that leads to
         * issuance), an issuance this application performed, and a failure the
         * prober found. Denials are counted, not stored.
         */
        Schema::create('certificate_issuance_attempts', function (Blueprint $table): void {
            $table->uuidKey();

            $table->string('host', 253)->collation('ascii_bin');

            /*
             * Denormalised rather than joined: §8.10.13 budgets "per
             * registered domain", the budget read happens on the issuance
             * path, and recomputing the registrable suffix per row at query
             * time would make the budget's own history unindexable.
             */
            $table->string('registered_domain', 253)->collation('ascii_bin');

            /*
             * `edge` is the fourth value and it is not one of §8.10.14's four
             * sources: it means the permission endpoint said yes and the
             * **proxy** went on to do the ACME exchange. DocUp never sees that
             * exchange — §8.10.17 is blunt that "the proxy never calls the
             * permission endpoint back on issuance failure" — so this row
             * records the permission, and the prober records the outcome.
             */
            $table->enum('source', ['public_acme', 'internal_acme', 'uploaded', 'development', 'edge']);
            $table->enum('outcome', ['permitted', 'issued', 'failed']);

            /*
             * A stable identifier rather than prose, so an operator can grep
             * for one cause and a dashboard can group by it.
             */
            $table->string('reason', 64)->nullable();
            $table->string('detail', 512)->nullable();

            $table->datetime('attempted_at', 3);
            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->index(['host', 'attempted_at'], 'cert_attempts_host_index');
            $table->index(['registered_domain', 'attempted_at'], 'cert_attempts_registered_index');
            $table->index('attempted_at', 'cert_attempts_time_index');
        });

        /*
         * §8.10.13's budget, modelled as the token bucket the CA actually
         * operates.
         *
         * 🛑 **§18.20 required re-reading the limits before freezing these
         * columns, and the re-read changed the shape rather than the
         * numbers.** Let's Encrypt's rate-limit page (last updated 2026-08-05)
         * states "New Certificates per Registered Domain" as a bucket of
         * **50 with a refill of one per 202 minutes**, not as a count inside a
         * seven-day window. The totals agree — 50 × 202 minutes is 7.01 days
         * — but the behaviour at the edge does not: a fixed window lets 50
         * issue in an hour and then refuses for a week, and refuses the 51st
         * even when the bucket has been refilling for two days. Storing the
         * bucket makes the application's answer the CA's answer.
         */
        Schema::create('issuance_budgets', function (Blueprint $table): void {
            $table->uuidKey();

            /*
             * 🛑 Not the hostname. The CA's bucket is keyed on the registrable
             * domain, so `a.example.com` and `b.example.com` share one, and a
             * budget keyed per host would report 49 remaining to each of fifty
             * subdomains that between them had exhausted it.
             */
            $table->string('registered_domain', 253)->collation('ascii_bin');

            /*
             * Tokens remaining and the instant that figure was true. Four
             * decimal places because the refill is 1/202 of a token per
             * minute: rounding to whole tokens on every read would lose every
             * refill shorter than three and a half hours, which for an
             * installation that checks often is every refill.
             */
            $table->decimal('tokens', 8, 4);
            $table->datetime('tokens_at', 3);

            /*
             * §8.10.13's "warning at 40". Recorded rather than recomputed so
             * the operator is told once rather than on every issuance after
             * the fortieth.
             */
            $table->datetime('warned_at', 3)->nullable();
            $table->datetime('blocked_at', 3)->nullable();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique('registered_domain', 'issuance_budgets_domain_unique');
        });

        Schema::table('domains', function (Blueprint $table): void {
            /*
             * §8.10.21. `passthrough` hands the TLS session to a corporate
             * load balancer, which is why it "MUST be refused on any
             * non-public project": the authorisation decision stops being
             * DocUp's. Default `managed` because the safe mode is the one
             * where this installation terminates and therefore enforces.
             */
            $table->enum('tls_mode', ['managed', 'passthrough'])
                ->default('managed')
                ->after('hsts_preload');

            /*
             * §8.10.13's per-host circuit breaker. Separate from
             * `check_failures`, which §8.10.6 uses for re-verification: a
             * hostname whose DNS is fine but whose issuance keeps failing is a
             * different fault with a different remedy, and sharing one counter
             * would let a verification success reset an issuance breaker.
             */
            $table->unsignedSmallInteger('issuance_failures')->default(0)->after('tls_mode');
            $table->datetime('issuance_blocked_until', 3)->nullable()->after('issuance_failures');

            /*
             * §8.10.17's prober writes these. They are the only record that
             * exists of what the edge actually served, because the edge does
             * not report issuance failures to anybody.
             */
            $table->datetime('tls_last_probed_at', 3)->nullable()->after('issuance_blocked_until');
            $table->datetime('tls_not_after', 3)->nullable()->after('tls_last_probed_at');
            $table->string('tls_issuer', 255)->nullable()->after('tls_not_after');
            $table->string('tls_probe_error', 255)->nullable()->after('tls_issuer');

            $table->index('issuance_blocked_until');
            $table->index('tls_not_after');
        });

        DataClassification::annotate('acme_accounts', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['label', 'operational', 'not_applicable', null, 'how config/tls.php names this account'],
            ['kind', 'operational', 'not_applicable', null, '§8.10.14 public or internal directory'],
            ['directory_url', 'operational', 'not_applicable', null, null],
            ['contact', 'personal', 'platform', null, 'operator contact address the CA mails'],
            ['account_url', 'operational', 'not_applicable', null, 'the ACME kid'],
            ['envelope_version', 'operational', 'not_applicable', null, '§9.1.7 envelope construction version'],
            ['kek_fingerprint', 'operational', 'not_applicable', null, 'which KEK wrapped this record'],
            ['wrapped_key', 'secret', 'not_applicable', 'credentials', '🛑 §9.1.7 data key, sealed under the KEK'],
            ['ciphertext', 'secret', 'not_applicable', 'credentials', '🛑 §8.10.15 ACME account key; never exported, never logged'],
            ['state', 'operational', 'not_applicable', null, null],
            ['registered_at', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('certificates', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['host', 'operational', 'not_applicable', null, null],
            ['active_host', 'derived', 'not_applicable', null, '🛑 one active certificate per host'],
            ['source', 'operational', 'not_applicable', null, '§8.10.14 four sources'],
            ['state', 'operational', 'not_applicable', null, null],
            ['organisation_id', 'operational', 'not_applicable', null, 'null for the installation wildcard'],
            ['domain_id', 'operational', 'not_applicable', null, null],
            ['acme_account_id', 'operational', 'not_applicable', null, null],
            ['chain_pem', 'operational', 'not_applicable', null, 'public by construction; every client receives it'],
            ['envelope_version', 'operational', 'not_applicable', null, '§9.1.7 envelope construction version'],
            ['kek_fingerprint', 'operational', 'not_applicable', null, 'which KEK wrapped this record'],
            ['wrapped_key', 'secret', 'not_applicable', 'credentials', '🛑 §9.1.7 data key, sealed under the KEK'],
            ['ciphertext', 'secret', 'not_applicable', 'credentials', '🛑 §8.10.15 certificate private key; every read audited'],
            ['serial', 'operational', 'not_applicable', null, null],
            ['issuer', 'operational', 'not_applicable', null, null],
            ['fingerprint', 'operational', 'not_applicable', null, 'sha256 of the DER leaf'],
            ['not_before', 'operational', 'not_applicable', null, null],
            ['not_after', 'operational', 'not_applicable', null, '§8.10.17 what the prober compares against'],
            ['activated_at', 'operational', 'not_applicable', null, null],
            ['superseded_at', 'operational', 'not_applicable', null, null],
            ['revoked_at', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('certificate_issuance_attempts', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['host', 'operational', 'not_applicable', null, null],
            ['registered_domain', 'operational', 'not_applicable', null, '§8.10.13 the budget key'],
            ['source', 'operational', 'not_applicable', null, "'edge' means the proxy issued, not this application"],
            ['outcome', 'operational', 'not_applicable', null, '🛑 denials are counted, never stored'],
            ['reason', 'operational', 'not_applicable', null, null],
            ['detail', 'operational', 'not_applicable', null, null],
            ['attempted_at', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('issuance_budgets', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['registered_domain', 'operational', 'not_applicable', null, "🛑 the CA's bucket key, not the hostname"],
            ['tokens', 'operational', 'not_applicable', null, '§8.10.13 bucket level; capacity 50'],
            ['tokens_at', 'operational', 'not_applicable', null, 'the instant `tokens` was true'],
            ['warned_at', 'operational', 'not_applicable', null, '§8.10.13 warning at 40'],
            ['blocked_at', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('domains', [
            ['tls_mode', 'operational', 'not_applicable', null, '🛑 §8.10.21 passthrough is refused on a non-public project'],
            ['issuance_failures', 'operational', 'not_applicable', null, '§8.10.13 circuit breaker'],
            ['issuance_blocked_until', 'operational', 'not_applicable', null, '§8.10.13 exponential backoff'],
            ['tls_last_probed_at', 'operational', 'not_applicable', null, '§8.10.17'],
            ['tls_not_after', 'operational', 'not_applicable', null, 'what the edge actually served'],
            ['tls_issuer', 'operational', 'not_applicable', null, null],
            ['tls_probe_error', 'operational', 'not_applicable', null, '🛑 the only issuance-failure observability there is'],
        ]);
    }

    public function down(): void
    {
        $columns = [
            'tls_mode',
            'issuance_failures',
            'issuance_blocked_until',
            'tls_last_probed_at',
            'tls_not_after',
            'tls_issuer',
            'tls_probe_error',
        ];

        DataClassification::forget('issuance_budgets');
        DataClassification::forget('certificate_issuance_attempts');
        DataClassification::forget('certificates');
        DataClassification::forget('acme_accounts');
        DataClassification::forget('domains', $columns);

        Schema::table('domains', function (Blueprint $table) use ($columns): void {
            $table->dropIndex(['tls_not_after']);
            $table->dropIndex(['issuance_blocked_until']);
            $table->dropColumn($columns);
        });

        Schema::dropIfExists('issuance_budgets');
        Schema::dropIfExists('certificate_issuance_attempts');
        Schema::dropIfExists('certificates');
        Schema::dropIfExists('acme_accounts');
    }
};
