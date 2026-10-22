<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\ApiTokens;
use App\Auth\Capability;
use App\Auth\Scope;
use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * A dashboard API token (§8.13.6).
 *
 * 🛑 One of the **two separate token families** §8.13.6 insists on keeping
 * apart: these authenticate a human's automation against the dashboard API.
 * Reader credentials are a different table, a different lifetime and a
 * different trust model, and conflating them is how a long-lived automation
 * token ends up granting documentation access.
 *
 * No `$fillable`: {@see ApiTokens} is the only thing that may mint
 * one, because minting is where §8.13.6's prohibition on installation-scope
 * administrative capability is enforced.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $user_id
 * @property string $name
 * @property string $token_hash
 * @property Scope $scope_type
 * @property string|null $scope_id
 * @property list<string> $capabilities
 * @property string $token_hash_prefix
 * @property Carbon|null $expires_at
 * @property Carbon|null $last_used_at
 * @property Carbon|null $revoked_at
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
final class ApiToken extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'capabilities' => 'array',
            'scope_type' => Scope::class,
            'expires_at' => 'datetime:Y-m-d H:i:s.v',
            'last_used_at' => 'datetime:Y-m-d H:i:s.v',
            'revoked_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    public function isUsable(): bool
    {
        return $this->revoked_at === null
            && $this->expires_at !== null
            && $this->expires_at->isFuture();
    }

    /** Whether this token carries a capability. */
    public function grants(Capability $capability): bool
    {
        return in_array($capability->value, $this->capabilities, true);
    }

    /** @return BelongsTo<User, $this> */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
