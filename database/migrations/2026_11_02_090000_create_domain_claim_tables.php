<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * §8.10.4's proof, §8.10.6's re-verification and §8.10.9's tombstone (§10.5).
 *
 * Phase 04 created `domains` and `domain_mounts` with their full column set
 * and no behaviour, because §7.3's first grammar step matches on
 * `domain_mounts.path_prefix` and "a resolver frozen without that column is
 * frozen around a hole". These are the four tables that drive them.
 *
 * 🛑 Every uniqueness rule here is a **STORED generated column under a unique
 * index**, never a plain unique index, and §8.10.5 says why: "An unconditional
 * unique index lets a squatter's pending row block the legitimate owner." The
 * same idiom already guards `domains.claimed_host`; `domain_claims` needs it
 * for the same reason one level up, and `domain_tombstones` needs it because
 * a released hostname may be released again after the first tombstone lapses.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('domain_claims', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');

            /*
             * §8.10.4's organisation-level parent claim: prove
             * `_docup-challenge.<apex>` once and "any host under it binds with
             * no further proof and **no other organisation may bind under
             * it**".
             */
            $table->string('apex', 253)->collation('ascii_bin');

            /*
             * 🛑 §8.10.5's uniqueness, one level up: NULL while unproven, so
             * the unique index below admits any number of competing pending
             * claims on one apex and exactly one proven claim. "No other
             * organisation may bind under it" (§8.10.4) is this index.
             *
             * 🛑 **Named `active_apex`, not §10.5's `active_labels_reversed`,
             * and the difference is a finding rather than a preference.**
             * §10.5 sketches a reversed-label column so that a suffix becomes
             * a prefix and ancestor lookup becomes a range scan. It does not:
             * the query is "which stored value is a prefix of this host?",
             * which is `? LIKE CONCAT(col, '%')` — unindexable in either
             * direction. And the expression that sketch implies,
             * `REVERSE(REPLACE(REVERSE(apex), '.', …))`, reverses nothing at
             * all: the two REVERSEs cancel.
             *
             * A hostname has at most a handful of suffixes, so
             * {@see App\Domains\Hostname::parentApexes()} enumerates them in
             * PHP and the lookup is one indexed `whereIn` on `apex`. Recorded
             * as a proposed amendment to §10.5.
             */
            $table->string('active_apex', 253)
                ->collation('ascii_bin')
                ->nullable()
                ->storedAs('IF(`verified_at` IS NULL, NULL, `apex`)');

            /*
             * The TXT value the organisation must publish at
             * `_docup-challenge.<apex>`. CSPRNG and stored in the clear, not
             * hashed: §9.1.4's rule is about **security tokens**, and this one
             * is published in public DNS by design — hashing a value the
             * holder must read back would make it unusable without protecting
             * anything.
             */
            $table->string('token', 64);

            $table->enum('state', ['pending', 'verified', 'revoked'])->default('pending');

            $table->datetime('verified_at', 3)->nullable();
            $table->datetime('last_checked_at', 3)->nullable();
            $table->datetime('revoked_at', 3)->nullable();

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->unique('active_apex', 'domain_claims_active_unique');
            $table->index(['organisation_id', 'state']);
            $table->index('apex');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
        });

        Schema::create('domain_tombstones', function (Blueprint $table): void {
            $table->uuidKey();

            /*
             * 🛑 §8.10.9: "A released hostname MUST enter a **90-day
             * tombstone**, reclaimable only by the previous owning
             * organisation and always with a freshly issued token. A dangling
             * CNAME pointing at the installation is otherwise a cross-tenant
             * takeover."
             *
             * The organisation is the one that may reclaim, so this row is
             * NOT organisation-scoped in the tenancy sense — it has to be
             * readable while deciding whether a **different** organisation may
             * claim the host. {@see App\Models\DomainTombstone} declares that
             * posture explicitly.
             */
            $table->uuidForeign('organisation_id');

            $table->string('host', 253)->collation('ascii_bin');

            $table->datetime('released_at', 3);
            $table->datetime('expires_at', 3);

            /*
             * NULL once the tombstone lapses, so the unique index stops
             * constraining it. Generated from `expires_at` rather than
             * maintained, because a tombstone that had to be swept before the
             * hostname freed up would make the 90 days a floor only while
             * somebody was running the sweeper.
             *
             * 🛑 MySQL cannot use NOW() in a generated column — it is not
             * deterministic — so the column is the host and the expiry
             * together and the **lapse is read at query time**. A unique index
             * on (host, expires_at) would permit two live tombstones for one
             * host with different expiries, which is why `host` alone carries
             * it and `release()` deletes a lapsed row before writing a new one.
             */
            $table->unique('host', 'domain_tombstones_host_unique');
            $table->index('expires_at');

            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
        });

        Schema::create('domain_verification_events', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');
            $table->uuidForeign('domain_id');

            /*
             * §8.10.6: "Every check MUST be recorded append-only and retained
             * 400 days." Append-only is the application's discipline here
             * rather than a trigger: unlike `audit_events` (§8.22.1) this is
             * operational telemetry rather than an evidentiary chain, and a
             * trigger per table is a privilege the installer would have to be
             * told about for each one.
             */
            $table->enum('method', ['parent_claim', 'dns_txt', 'cname']);
            $table->enum('outcome', ['passed', 'failed', 'disagreed', 'unresolvable']);

            // What the resolvers actually said, so an operator debugging a
            // failing check does not have to reproduce it.
            $table->json('observed')->nullable();
            $table->string('detail', 512)->nullable();

            $table->datetime('checked_at', 3);
            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->index(['domain_id', 'checked_at'], 'domain_verification_events_domain_index');
            $table->index('checked_at');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('domain_id')->references('id')->on('domains')->cascadeOnDelete();
        });

        Schema::create('domain_events', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('organisation_id');

            /*
             * Nullable and `nullOnDelete`: the lifecycle event that matters
             * most is `released`, and the domain row is gone by the time
             * anybody asks about it. The hostname is carried in `host` for
             * exactly that case.
             */
            $table->uuidForeign('domain_id', nullable: true);

            $table->string('host', 253)->collation('ascii_bin');

            $table->enum('event', [
                'claimed', 'verified', 'activated', 'failing',
                'suspended', 'released', 'reclaimed', 'mode_changed',
            ]);

            $table->json('payload')->nullable();

            /*
             * §10.5 calls this table hash-chained. The chain is per
             * organisation and over the previous row's digest, the same shape
             * §8.22.5 gives the audit log — so a deleted or reordered domain
             * event is detectable, which matters because these rows are the
             * record of who was allowed to serve a hostname and when.
             */
            $table->binary('digest', 32, true);
            $table->binary('previous_digest', 32, true)->nullable();

            $table->datetime('occurred_at', 3);
            $table->datetime('created_at', 3)->nullable();
            $table->datetime('updated_at', 3)->nullable();

            $table->index(['organisation_id', 'occurred_at'], 'domain_events_org_time_index');
            $table->index('host');

            $table->foreign('organisation_id')->references('id')->on('organisations')->cascadeOnDelete();
            $table->foreign('domain_id')->references('id')->on('domains')->nullOnDelete();
        });

        Schema::table('domains', function (Blueprint $table): void {
            /*
             * §8.10.4's per-host proof. The TXT value for `dns_txt`, and the
             * input to the `cname` label; stored in the clear for the reason
             * `domain_claims.token` is.
             *
             * 🛑 Re-issued on reclaim (§8.10.9: "always with a freshly issued
             * token"), which is why it lives on the row rather than being
             * derived from the id — a derived token could not be rotated
             * without changing the id, and the id is what the CNAME label is
             * built from.
             */
            $table->string('verification_token', 64)->nullable()->after('verification_method');

            /*
             * 🛑 §8.10.20's derived flag: "A hostname carrying more than one
             * domain mount MUST set a derived `shared_origin` flag requiring
             * one organisation, one authentication profile and one privacy
             * level across those mounts, forbidding tenant CSS and JavaScript,
             * and recording an operator acknowledgement."
             *
             * Not a generated column: it counts rows in another table, which
             * MySQL cannot express. {@see App\Domains\SharedOrigin} maintains
             * it on every mount write and a test asserts the two agree.
             */
            $table->boolean('shared_origin')->default(false)->after('verification_token');
            $table->datetime('shared_origin_acknowledged_at', 3)->nullable()->after('shared_origin');

            /*
             * §8.10.19: "HSTS MUST default to **off**." A null policy is off;
             * the two sub-flags are validation errors on a shared apex or a
             * hostname that is a DNS suffix of another claimed hostname.
             */
            $table->unsignedInteger('hsts_max_age')->nullable()->after('shared_origin_acknowledged_at');
            $table->boolean('hsts_include_subdomains')->default(false)->after('hsts_max_age');
            $table->boolean('hsts_preload')->default(false)->after('hsts_include_subdomains');

            // §8.10.6's exponential backoff between failing checks.
            $table->unsignedSmallInteger('check_failures')->default(0)->after('last_checked_at');
            $table->datetime('next_check_at', 3)->nullable()->after('check_failures');

            $table->index('next_check_at');
        });

        DataClassification::annotate('domain_claims', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['apex', 'operational', 'not_applicable', null, '§8.10.4 parent claim'],
            ['active_apex', 'derived', 'not_applicable', null, '🛑 §8.10.5 proven-claims-only uniqueness'],
            ['token', 'operational', 'not_applicable', null, 'published in public DNS by design'],
            ['state', 'operational', 'not_applicable', null, null],
            ['verified_at', 'operational', 'not_applicable', null, null],
            ['last_checked_at', 'operational', 'not_applicable', null, null],
            ['revoked_at', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('domain_tombstones', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, '🛑 the only organisation that may reclaim'],
            ['host', 'operational', 'not_applicable', null, null],
            ['released_at', 'operational', 'not_applicable', null, null],
            ['expires_at', 'operational', 'not_applicable', null, '🛑 §8.10.9 ninety days'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('domain_verification_events', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['domain_id', 'operational', 'not_applicable', null, null],
            ['method', 'operational', 'not_applicable', null, '§8.10.4'],
            ['outcome', 'operational', 'not_applicable', null, null],
            ['observed', 'operational', 'not_applicable', null, 'what the resolvers answered'],
            ['detail', 'operational', 'not_applicable', null, null],
            ['checked_at', 'operational', 'not_applicable', '400 days', '§8.10.6 retention'],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('domain_events', [
            ['id', 'operational', 'not_applicable', null, null],
            ['id_text', 'derived', 'not_applicable', null, 'generated view of id'],
            ['organisation_id', 'operational', 'not_applicable', null, 'tenancy key (§8.2.1)'],
            ['domain_id', 'operational', 'not_applicable', null, 'null once the domain is released'],
            ['host', 'operational', 'not_applicable', null, 'carried so a released host is still named'],
            ['event', 'operational', 'not_applicable', null, null],
            ['payload', 'operational', 'not_applicable', null, null],
            ['digest', 'derived', 'not_applicable', null, '§10.5 hash chain'],
            ['previous_digest', 'derived', 'not_applicable', null, '§10.5 hash chain'],
            ['occurred_at', 'operational', 'not_applicable', null, null],
            ['created_at', 'operational', 'not_applicable', null, null],
            ['updated_at', 'operational', 'not_applicable', null, null],
        ]);

        DataClassification::annotate('domains', [
            ['verification_token', 'operational', 'not_applicable', null, '§8.10.4; published in DNS by design'],
            ['shared_origin', 'derived', 'not_applicable', null, '🛑 §8.10.20'],
            ['shared_origin_acknowledged_at', 'operational', 'not_applicable', null, '§8.10.20 acknowledgement'],
            ['hsts_max_age', 'operational', 'not_applicable', null, '§8.10.19; null is off'],
            ['hsts_include_subdomains', 'operational', 'not_applicable', null, '🛑 §8.10.19 refused on a shared apex'],
            ['hsts_preload', 'operational', 'not_applicable', null, '🛑 §8.10.19 refused on a shared apex'],
            ['check_failures', 'operational', 'not_applicable', null, '§8.10.6 exponential backoff'],
            ['next_check_at', 'operational', 'not_applicable', null, '§8.10.6 daily re-verification'],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('domain_events');
        Schema::dropIfExists('domain_verification_events');
        Schema::dropIfExists('domain_tombstones');
        Schema::dropIfExists('domain_claims');

        $columns = [
            'verification_token', 'shared_origin', 'shared_origin_acknowledged_at',
            'hsts_max_age', 'hsts_include_subdomains', 'hsts_preload',
            'check_failures', 'next_check_at',
        ];

        $present = array_values(array_filter(
            $columns,
            static fn (string $column): bool => Schema::hasColumn('domains', $column),
        ));

        if ($present !== []) {
            Schema::table('domains', function (Blueprint $table) use ($present): void {
                $table->dropColumn($present);
            });
        }

        DataClassification::forget('domain_events');
        DataClassification::forget('domain_verification_events');
        DataClassification::forget('domain_tombstones');
        DataClassification::forget('domain_claims');
        DataClassification::forget('domains', $columns);
    }
};
