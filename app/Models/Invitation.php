<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Invitations;
use App\Auth\Role;
use App\Auth\Scope;
use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A single-use, hashed, email-bound invitation (§8.2.4).
 *
 * 🛑 No `$fillable`. Every field is decided by {@see Invitations},
 * which is the only thing that may create one: an invitation carries a
 * pre-staged role grant, so a mass-assignable `role` column is a privilege
 * escalation waiting for a controller that forwards request data.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $email
 * @property string $token_hash
 * @property Role $role
 * @property Scope $scope_type
 * @property string|null $scope_id
 * @property string $invited_by
 * @property string $token_hash_prefix
 * @property Carbon|null $expires_at
 * @property Carbon|null $accepted_at
 * @property Carbon|null $revoked_at
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
final class Invitation extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'role' => Role::class,
            'scope_type' => Scope::class,
            'expires_at' => 'datetime:Y-m-d H:i:s.v',
            'accepted_at' => 'datetime:Y-m-d H:i:s.v',
            'revoked_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /**
     * Whether this invitation can still be accepted.
     *
     * All three conditions, because each fails differently: expired is time,
     * accepted is §8.2.4's single-use rule, revoked is an administrator
     * changing their mind. Treating them as one check would make the UI unable
     * to say which happened.
     */
    public function isOpen(): bool
    {
        return $this->accepted_at === null
            && $this->revoked_at === null
            && $this->expires_at !== null
            && $this->expires_at->isFuture();
    }

    /**
     * 🛑 §8.13.4: MFA is required above `project_writer`, and §8.2.4 requires
     * enrolment to be forced on acceptance where policy demands it. Asked of
     * the pre-staged role, so the answer cannot drift from the role actually
     * being granted.
     */
    public function forcesMfaEnrolment(): bool
    {
        return $this->role->requiresMfa();
    }
}
