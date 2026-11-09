<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * §8.15's per-project addons settings, plus §8.14.16's resolved CSP value.
 *
 * Five columns, three concerns:
 *
 * - §8.15.6's **per-project toggles** for the three notification banners.
 *   The requirement names them together — "three **notification banners** […]
 *   with stated trigger conditions and per-project toggles" — so they are three
 *   columns rather than one bitfield: an operator turning off the old-version
 *   banner is making a different editorial decision from one turning off the
 *   pull-request banner, and a shared column would make the two indistinguishable
 *   in an audit.
 *
 * - §8.15.12's **search takeover**, which is a `SHOULD` for the takeover and a
 *   `MUST` for leaving the generator's own search alone when it is disabled. So
 *   the toggle has to exist for the `MUST` to be expressible at all.
 *
 * - 🛑 §8.14.16's **resolved** `frame-ancestors`, denormalised onto the project.
 *   See the column's own comment; this is the half Phase 27 recorded as owed.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('projects', function (Blueprint $table): void {
            /*
             * §8.15.6's three banners, each defaulting ON.
             *
             * 🛑 On by default because they are the reader-facing half of
             * §8.6's version model: a reader who has landed on `v1.2` from a
             * two-year-old blog post and is not told so will file a bug against
             * documentation that was corrected long ago. §8.15.6 calls them "the
             * most reader-visible Read the Docs feature after the flyout", and a
             * parity feature that ships off is a parity feature nobody migrating
             * finds.
             */
            $table->boolean('notify_old_version')->default(true);
            $table->boolean('notify_development_version')->default(true);
            $table->boolean('notify_pull_request')->default(true);

            /*
             * §8.15.12's takeover of a generator's own search affordance.
             *
             * Defaults ON, because the addons search is the one that can filter
             * by §12.3 access and a generator's inlined index cannot — but the
             * selector is configurable and the toggle is what §8.15.12's MUST
             * needs: "MUST leave the generator's own search working untouched
             * when `chrome_mode` is `off` or takeover is disabled".
             */
            $table->boolean('addons_search_takeover')->default(true);

            /*
             * §8.15.12's selector, with the requirement's own default.
             *
             * Nullable rather than defaulted in the schema, so "the project has
             * not chosen" is distinguishable from "the project chose the
             * default" — the first follows a later release that changes the
             * default and the second does not.
             */
            $table->string('addons_search_selector', 255)->nullable();

            /*
             * 🛑 §8.14.16's `frame-ancestors`, RESOLVED through the §8.14.1
             * cascade and stored here.
             *
             * The token cascades installation → organisation → project, and
             * emitting it on a document response needs the resolved value in the
             * routing snapshot — §9.2 has no room for a theme resolution per
             * document request, and §8.9.1 requires the resolver to run "with no
             * database queries". A column the snapshot query already selects
             * costs nothing on that path.
             *
             * This is the same denormalisation `resolved_stable_version_id` and
             * `resolved_latest_version_id` already use in this table: a value
             * derived by a rule, written when the inputs change, read on the hot
             * path. 🛑 And it is derived rather than authored, so nothing may
             * write it but the theme publish path — see
             * App\Branding\ResolvedFrameAncestors.
             *
             * Nullable means "never resolved", which reads as the token's own
             * default (`'self'`). A project that has never had a theme published
             * must still get a CSP, and the strictest sensible value is the one
             * the registry already defaults to.
             */
            $table->string('resolved_frame_ancestors', 1024)->nullable();
        });

        DataClassification::annotate('projects', [
            ['notify_old_version', 'operational', 'not_applicable', null, '§8.15.6 per-project banner toggle'],
            ['notify_development_version', 'operational', 'not_applicable', null, '§8.15.6 per-project banner toggle'],
            ['notify_pull_request', 'operational', 'not_applicable', null, '§8.15.6 per-project banner toggle'],
            ['addons_search_takeover', 'operational', 'not_applicable', null, '§8.15.12 takeover toggle'],
            ['addons_search_selector', 'operational', 'not_applicable', null, '§8.15.12 selector override'],
            ['resolved_frame_ancestors', 'operational', 'not_applicable', null, '🛑 §8.14.16 resolved for the §8.9.1 snapshot'],
        ]);
    }

    public function down(): void
    {
        Schema::table('projects', function (Blueprint $table): void {
            $table->dropColumn([
                'notify_old_version',
                'notify_development_version',
                'notify_pull_request',
                'addons_search_takeover',
                'addons_search_selector',
                'resolved_frame_ancestors',
            ]);
        });

        DataClassification::forget('projects', [
            'notify_old_version',
            'notify_development_version',
            'notify_pull_request',
            'addons_search_takeover',
            'addons_search_selector',
            'resolved_frame_ancestors',
        ]);
    }
};
