<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Builds\FailureClass;
use App\Builds\Stage;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * One attempt at one of §8.5.6's twelve stages.
 *
 * These rows are what Phase 06's exit criterion means by "watch step rows
 * advance": progress is a query against this table, not a log scrape. That
 * distinction matters beyond the demo — a log is a stream somebody has to be
 * watching, and a row is a fact anybody can ask about afterwards.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $build_id
 * @property Stage $stage
 * @property int $sequence
 * @property string $state
 * @property int $attempt
 * @property string|null $lease_owner
 * @property Carbon|null $lease_expires_at
 * @property int $lease_renewals
 * @property Carbon|null $started_at
 * @property Carbon|null $finished_at
 * @property int|null $exit_code
 * @property FailureClass|null $failure_class
 * @property string|null $failure_identifier
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
final class BuildStep extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @var array<string, mixed> */
    protected $attributes = [
        'state' => 'pending',
        'attempt' => 1,
        'lease_renewals' => 0,
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'stage' => Stage::class,
            'failure_class' => FailureClass::class,
            'sequence' => 'integer',
            'attempt' => 'integer',
            'lease_renewals' => 'integer',
            'lease_expires_at' => 'datetime:Y-m-d H:i:s.v',
            'started_at' => 'datetime:Y-m-d H:i:s.v',
            'finished_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<Build, $this> */
    public function build(): BelongsTo
    {
        return $this->belongsTo(Build::class);
    }

    /** The step is held by a runner whose lease has not yet expired. */
    public function isLeased(): bool
    {
        return $this->lease_expires_at !== null && $this->lease_expires_at->isFuture();
    }

    /**
     * The lease has lapsed while the step was still running — the runner died.
     *
     * 🛑 Distinguished from "not yet claimed" by the state, not by the lease.
     * A `pending` step with no lease is waiting; a `running` step with an
     * expired lease is abandoned work, and only the second needs reclaiming.
     */
    public function isAbandoned(): bool
    {
        return $this->state === 'running'
            && $this->lease_expires_at !== null
            && $this->lease_expires_at->isPast();
    }
}
