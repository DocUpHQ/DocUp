<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The project-side columns §7.3's grammar resolves against (§10.4).
 *
 * 🛑 Added in **Phase 04**, not later, because §17 freezes the `Resolver` and
 * the §7.3 path grammar at the end of this phase — and that freeze "is only
 * honest because P04 implements the **full** grammar". A resolver written
 * without `url_prefix` or `versioning_scheme` would be frozen around a hole, and
 * every later phase would merely be populating tables it could no longer shape.
 *
 * §10.4 lists more project columns than these — `multi_domain_mode`,
 * `source_policy`, `egress_mode`, `merge_policy`, `preview_policy`,
 * `deny_status`, `authz_epoch` and others. They are deliberately absent: §4.3
 * forbids a column for a thing that does not exist yet, and each belongs to the
 * phase that gives it meaning. The four here are the ones the resolver and the
 * serving edge read on this phase's hot path.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('projects', function (Blueprint $table): void {
            /*
             * §8.6.9's three schemes, verbatim: `lang_and_version`
             * (`/{lang}/{version}/{file}`), `multi_version` (`/{version}/{file}`)
             * and `single_version` (`/{file}`). This column decides which
             * segments §7.3's version step consumes, so the resolver cannot be
             * written without it.
             *
             * `lang_and_version` by default, matching Read the Docs' own shape
             * (§3): a migrating project's existing URLs keep working, and §20.4's
             * compatibility promise is about URLs more than anything else.
             */
            $table->enum('versioning_scheme', ['lang_and_version', 'multi_version', 'single_version'])
                ->default('lang_and_version')
                ->after('visibility');

            /*
             * §7.3's `[project.url_prefix]` step. Nullable because most projects
             * have none: the prefix exists for the path-portal hosting shape
             * (§8.10.1), where several projects share one domain under different
             * prefixes.
             */
            $table->string('url_prefix', 100)->nullable()->after('versioning_scheme');

            /*
             * 🛑 §8.6.14: an explicit stored pointer, "not a derived value,
             * because §8.9.7's empty-path redirect, §8.6.11's `/page/<filename>`
             * resolution and §8.11.5's 404 chain all depend on it". Phase 04
             * owns the first of those three, which is why the column lands here.
             *
             * No foreign key to `project_versions`: §8.6.14 requires the pointer
             * to be "re-pointed automatically with an audit event when its target
             * is deleted or deactivated", and a cascade would delete the pointer
             * silently instead — losing the event that is the point of the
             * requirement. The re-point behaviour arrives with versions in a
             * later phase; until then an orphaned pointer resolves to nothing,
             * which is a 404 rather than a wrong page.
             */
            $table->uuidForeign('default_version_id', nullable: true);

            /*
             * 🛑 §8.9.10 and §10.8: the resolution cache keys on this
             * (`res:{routing_epoch}:{host}:{sha1(path)}`) rather than being
             * purged. Maximum tolerated staleness is **0**, which is exactly
             * what putting it in the key buys — there is no window in which a
             * stale entry can be read, because a bumped epoch addresses
             * different keys.
             *
             * Per **project**, not global, and §8.9.10 says why: "one project's
             * domain change cannot invalidate every other project's resolution
             * cache". A single installation-wide counter would make every domain
             * edit a full cache flush.
             */
            $table->unsignedBigInteger('routing_epoch')->default(1);

            /*
             * §8.15.7: `injected` (default), `api_only`, `off`. Phase 04 injects
             * at ingest and needs the fallback target, because §8.15.4 requires
             * an artifact that cannot be injected to "fall back to
             * `chrome_mode: api_only` for that build".
             */
            $table->enum('chrome_mode', ['injected', 'api_only', 'off'])->default('injected');
        });

        DataClassification::annotate('projects', [
            ['versioning_scheme', 'operational', 'not_applicable', null, '§8.6.9; decides §7.3 version segments'],
            ['url_prefix', 'operational', 'not_applicable', null, "§7.3's project prefix step"],
            ['default_version_id', 'operational', 'not_applicable', null, '🛑 §8.6.14 explicit pointer, not derived'],
            ['routing_epoch', 'operational', 'not_applicable', null, '§8.9.10 in the resolution cache key'],
            ['chrome_mode', 'operational', 'not_applicable', null, '§8.15.7; §8.15.4 falls back to api_only'],
        ]);
    }

    public function down(): void
    {
        Schema::table('projects', function (Blueprint $table): void {
            $table->dropColumn([
                'versioning_scheme',
                'url_prefix',
                'default_version_id',
                'routing_epoch',
                'chrome_mode',
            ]);
        });

        DataClassification::forget('projects', [
            'versioning_scheme',
            'url_prefix',
            'default_version_id',
            'routing_epoch',
            'chrome_mode',
        ]);
    }
};
