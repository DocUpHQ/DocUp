<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Role;
use App\Auth\Scope;
use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * One grant of one role to one subject at one scope (§10.1, §12.1).
 *
 * @property-read string $id
 * @property string|null $organisation_id
 * @property string $subject_type
 * @property string $subject_id
 * @property Scope $scope_type
 * @property string|null $scope_id
 * @property Role $role
 * @property string $source
 * @property Carbon|null $expires_at
 */
#[Tenancy(
    TenancyPosture::Installation,
    because: 'This table holds installation-scope grants with a NULL organisation_id, and the '
        .'global scope would filter exactly those away — an installation owner would lose '
        .'every capability the moment a tenant context was declared. Reads for '
        .'authorisation go through RoleResolver, which queries the builder directly for '
        .'this reason; any listing UI must filter by organisation explicitly.'
)]
#[Fillable(['organisation_id', 'subject_type', 'subject_id', 'scope_type', 'scope_id', 'role', 'source', 'expires_at'])]
final class RoleAssignment extends Model
{
    use HasUuidKey;

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'scope_type' => Scope::class,
            'role' => Role::class,
            'expires_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** Whether this grant is in force right now. */
    public function isActive(): bool
    {
        return $this->expires_at === null || $this->expires_at->isFuture();
    }
}
