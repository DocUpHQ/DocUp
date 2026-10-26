<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use App\Serving\RoutingSnapshotLoader;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;

/**
 * A serving hostname and its §8.10.6 state machine (§10.5).
 *
 * The table has existed since Phase 04 with its full column set and nothing
 * driving it. This model, and `App\Domains`, are what drive it.
 *
 * 🛑 `claimed_host` is a STORED generated column and the application never
 * writes it: it is NULL while `verified_at` is, and carries §8.10.5's unique
 * index otherwise, so a squatter's pending row cannot block the legitimate
 * owner. Listed in `$guarded` so an attempt to set it fails as the
 * programming mistake it is rather than as a query error.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $host punycode A-labels, lowercase (§8.10.7)
 * @property string $kind default_subdomain, custom, apex or preview
 * @property string $state 🛑 §8.10.6: pending → verified → active → failing → suspended
 * @property string|null $verification_method
 * @property string|null $verification_token published in DNS by design
 * @property bool $shared_origin 🛑 §8.10.20, derived from the mount count
 * @property int|null $hsts_max_age §8.10.19; null is off
 * @property bool $hsts_include_subdomains
 * @property bool $hsts_preload
 * @property int $check_failures
 * @property Carbon|null $verified_at
 * @property Carbon|null $last_checked_at
 * @property Carbon|null $next_check_at
 * @property Carbon|null $failing_since
 * @property Carbon|null $suspended_at
 * @property Carbon|null $shared_origin_acknowledged_at
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['host', 'kind', 'hsts_max_age', 'hsts_include_subdomains', 'hsts_preload'])]
final class Domain extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @var list<string> */
    protected $guarded = ['id', 'claimed_host'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'kind' => 'custom',
        'state' => 'pending',
        'shared_origin' => false,
        'hsts_include_subdomains' => false,
        'hsts_preload' => false,
        'check_failures' => 0,
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'shared_origin' => 'boolean',
            'hsts_include_subdomains' => 'boolean',
            'hsts_preload' => 'boolean',
            'check_failures' => 'integer',
            'verified_at' => 'datetime:Y-m-d H:i:s.v',
            'last_checked_at' => 'datetime:Y-m-d H:i:s.v',
            'next_check_at' => 'datetime:Y-m-d H:i:s.v',
            'failing_since' => 'datetime:Y-m-d H:i:s.v',
            'suspended_at' => 'datetime:Y-m-d H:i:s.v',
            'shared_origin_acknowledged_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return HasMany<DomainMount, $this> */
    public function mounts(): HasMany
    {
        return $this->hasMany(DomainMount::class);
    }

    /**
     * 🛑 §8.10.6: "Suspended and unverified hosts MUST be neither served nor
     * certified."
     *
     * Delegated to the serving path's own predicate rather than restated, so
     * the dashboard and the resolver cannot disagree about whether a host is
     * live.
     */
    public function canServe(): bool
    {
        return RoutingSnapshotLoader::canServe(
            $this->kind,
            $this->state,
            $this->verified_at?->toDateTimeString(),
        );
    }

    /** Whether proof has ever been accepted for this hostname. */
    public function isProven(): bool
    {
        return $this->verified_at !== null;
    }
}
