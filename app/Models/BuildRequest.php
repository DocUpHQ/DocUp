<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * One normalised trigger (§8.5.3).
 *
 * 🛑 **`unchanged`, `skipped` and `superseded` are terminal and are not
 * failures.** §8.5.4 is explicit that a skip rule "MUST resolve to `skipped`
 * and never `failed`", and §8.5.2 gives the digest short-circuit its own
 * terminal state. The three are separate because an operator staring at a
 * version that is not rebuilding needs to know which happened: the inputs were
 * identical, a rule they wrote said no, or a newer request replaced this one.
 * Collapsing them into one "not built" state is how a misconfigured skip rule
 * goes unnoticed for a month.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $project_version_id
 * @property string|null $component_id
 * @property string $trigger
 * @property string|null $integration_id
 * @property string|null $delivery_id
 * @property string|null $requested_by
 * @property string $state
 * @property string|null $outcome_identifier
 * @property string|null $plan_digest
 * @property string|null $build_id
 * @property bool $payload_truncated
 * @property Carbon|null $created_at
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
final class BuildRequest extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** States from which nothing further happens. */
    public const TERMINAL = ['completed', 'unchanged', 'skipped', 'superseded', 'rejected', 'failed'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'state' => 'queued',
        'payload_truncated' => false,

        /*
         * 🛑 §8.5.10's default, declared on the model as well as in the
         * schema. A request built in memory and never saved - which is how
         * most of the pipeline's tests construct one - would otherwise read
         * `null` here, and `null !== true` is the right answer by accident
         * rather than by statement.
         */
        'from_fork' => false,
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'payload_truncated' => 'boolean',
            'from_fork' => 'boolean',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<ProjectVersion, $this> */
    public function version(): BelongsTo
    {
        return $this->belongsTo(ProjectVersion::class, 'project_version_id');
    }

    /** @return BelongsTo<Build, $this> */
    public function build(): BelongsTo
    {
        return $this->belongsTo(Build::class);
    }

    public function isTerminal(): bool
    {
        return in_array($this->state, self::TERMINAL, true);
    }

    /**
     * Settle the request without a build.
     *
     * One method for the three non-failure outcomes, so the identifier is
     * always set alongside the state. A state without its identifier is a
     * request whose reason was lost, and the reason is the whole value of
     * distinguishing them.
     */
    public function settle(string $state, string $outcomeIdentifier): void
    {
        $this->forceFill([
            'state' => $state,
            'outcome_identifier' => $outcomeIdentifier,
        ])->save();
    }
}
