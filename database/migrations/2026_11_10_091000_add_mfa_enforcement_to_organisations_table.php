<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Auth\MfaEnforcement;
use App\Support\DataClassification;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * §8.13.4's organisation half: "MFA MUST be enforceable **per installation and
 * per organisation**".
 *
 * 🛑 **Two scopes, two mechanisms, and the asymmetry is deliberate.** The
 * installation switch is `DOCUP_MFA_REQUIRED` in configuration, because it
 * belongs to whoever runs the server and §11's deployment profile makes that a
 * person with shell access and a `.env`. The organisation switch is this
 * column, because it belongs to whoever runs the organisation — a tenant
 * administrator with no shell, and §12.1's `org_admin` is exactly that role.
 *
 * A single mechanism would get one of the two wrong: a column for the
 * installation would make a security posture editable by anybody who can reach
 * the database, and configuration per organisation would mean an operator
 * editing `.env` and restarting PHP every time a tenant asked.
 *
 * 🛑 **The installation switch dominates.** See
 * {@see MfaEnforcement}: an organisation cannot turn off a
 * requirement the installation imposes, which is the only ordering that makes
 * the installation switch worth having.
 *
 * Default **false**, and that is a product decision rather than a weak one.
 * §8.13.4 says "enforceable", not "enforced"; an installation that turned this
 * on at migration time would lock every existing administrator out of their own
 * dashboard on upgrade, including the one who would have to turn it off.
 * `doctor` surfacing the recommendation is §15's job.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('organisations', function (Blueprint $table): void {
            $table->boolean('mfa_required')->default(false)->after('default_timezone');
        });

        DataClassification::annotate('organisations', [
            ['mfa_required', 'operational', 'not_applicable', null, '🛑 §8.13.4: enforceable per organisation; the installation switch dominates'],
        ]);
    }

    public function down(): void
    {
        Schema::table('organisations', function (Blueprint $table): void {
            $table->dropColumn('mfa_required');
        });
    }
};
