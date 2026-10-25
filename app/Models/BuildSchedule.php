<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Automation\CronSchedule;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * §8.5.3's "native per-version cron schedule".
 *
 * 🛑 **Native**, as opposed to Read the Docs' answer, which is to tell the
 * operator to run a cron job that calls the API. A schedule the product owns
 * can state its DST semantics (§8.22.13), can be read back through the API
 * (§8.19.1), and survives the operator's crontab being lost with the host it
 * lived on.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $project_id
 * @property string|null $project_version_id
 * @property string $cron_expression
 * @property string $timezone
 * @property bool $enabled
 * @property CarbonImmutable|null $last_run_at
 * @property CarbonImmutable|null $next_run_at
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['project_version_id', 'cron_expression', 'timezone', 'enabled'])]
final class BuildSchedule extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @var array<string, mixed> */
    protected $attributes = [
        'timezone' => 'UTC',
        'enabled' => true,
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'enabled' => 'boolean',
            'last_run_at' => 'immutable_datetime:Y-m-d H:i:s.v',
            'next_run_at' => 'immutable_datetime:Y-m-d H:i:s.v',
            'created_at' => 'immutable_datetime:Y-m-d H:i:s.v',
            'updated_at' => 'immutable_datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<Project, $this> */
    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class);
    }

    /** @return BelongsTo<ProjectVersion, $this> */
    public function version(): BelongsTo
    {
        return $this->belongsTo(ProjectVersion::class, 'project_version_id');
    }

    public function schedule(): CronSchedule
    {
        return new CronSchedule($this->cron_expression, $this->timezone);
    }

    /**
     * Move `next_run_at` past the instant just fired.
     *
     * 🛑 Computed from the instant that fired, not from "now", so a
     * scheduler that ran four minutes late does not push every subsequent
     * run four minutes later — and a nightly build stays nightly rather
     * than drifting into the working day over a month.
     */
    public function advance(CarbonImmutable $firedAt): void
    {
        $this->forceFill([
            'last_run_at' => $firedAt,
            'next_run_at' => $this->schedule()->nextAfter($firedAt),
        ])->save();
    }
}
