<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use App\Source\Provider;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * A git repository connected once and attachable many times (§8.3.2, §10.2).
 *
 * 🛑 The resolution order in {@see locate()} is the §8.3.8 requirement made
 * executable, and the order is the whole point: **stable identifier first,
 * normalised URL only as a fallback.** A repository renamed at the provider
 * has a new URL and the same identifier; looking the URL up first would miss
 * it, create a duplicate row, and orphan every component that pointed at the
 * original. ADR 0009 verified that all five providers in §8.3.1 supply such an
 * identifier at attach time and in webhooks, which is what makes this order
 * possible at all.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property Provider $provider
 * @property string $provider_host
 * @property string|null $provider_repo_id
 * @property string $normalised_url
 * @property string $clone_url
 * @property bool $submodules_enabled
 * @property string $webhook_state
 * @property string $state
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable([
    'provider', 'provider_host', 'provider_repo_id', 'normalised_url',
    'clone_url', 'default_branch', 'submodules_enabled', 'credential_id',
])]
final class Repository extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;
    use SoftDeletes;

    /** @var array<string, mixed> */
    protected $attributes = [
        'submodules_enabled' => false,
        'webhook_state' => 'unprovisioned',
        'state' => 'active',
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'provider' => Provider::class,
            'submodules_enabled' => 'boolean',
            'webhook_checked_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
            'deleted_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<RepositoryCredential, $this> */
    public function credential(): BelongsTo
    {
        return $this->belongsTo(RepositoryCredential::class, 'credential_id');
    }

    /** @return HasMany<ComponentSource, $this> */
    public function sources(): HasMany
    {
        return $this->hasMany(ComponentSource::class);
    }

    /**
     * Find an already-connected repository, by identifier where one exists and
     * by normalised URL where one does not.
     *
     * 🛑 This is the §8.3.2 "connected once" guarantee and the §8.3.8 rename
     * tolerance, in one place. Phase 05's exit criterion — "a repository
     * renamed at the provider still resolves by its stable identifier" — is
     * this method returning the original row when the URL no longer matches.
     *
     * The host is part of the identifier lookup because the identifier is
     * unique **per instance**: Gitea repository 42 exists on every Gitea
     * server (ADR 0009).
     */
    public static function locate(
        Provider $provider,
        string $providerHost,
        ?string $providerRepoId,
        string $normalisedUrl,
    ): ?self {
        if ($providerRepoId !== null) {
            $byIdentifier = self::query()
                ->where('provider', $provider->value)
                ->where('provider_host', $providerHost)
                ->where('provider_repo_id', $providerRepoId)
                ->first();

            if ($byIdentifier instanceof self) {
                return $byIdentifier;
            }
        }

        /*
         * The fallback. 🛑 It runs even when an identifier was supplied,
         * because the row may predate the identifier being recorded — a
         * repository attached as `generic` and later recognised, or one
         * attached before this phase existed. Returning null there would
         * create a duplicate under the URL's unique index and fail the insert
         * with a constraint error instead of linking the row.
         */
        $byUrl = self::query()->where('normalised_url', $normalisedUrl)->first();

        return $byUrl instanceof self ? $byUrl : null;
    }

    /** @param  Builder<self>  $query */
    public function scopeAttachable(Builder $query): void
    {
        $query->where('state', 'active');
    }
}
