<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * A named set of people within an organisation (§8.2.3).
 *
 * 🛑 §12.1 is explicit that team membership and permission resolution are
 * different things: the starter kit's Teams scaffolding is used for
 * *membership*, and roles resolve through `role_assignments`. There is
 * deliberately no role column here — a team is a convenient way to name a group
 * of people, not an authorisation primitive.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $name
 * @property string $slug
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['name', 'slug'])]
final class Team extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;
    use SoftDeletes;

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
            'deleted_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /**
     * 🛑 The relation ADR 0006 measured returning silently empty under an
     * attribute cast, across a `BINARY(16)` pivot. It works because
     * {@see HasUuidKey} holds raw bytes; `tests/Feature/UuidKeyTest.php` asserts
     * the general case against real MySQL.
     *
     * @return BelongsToMany<User, $this>
     */
    public function members(): BelongsToMany
    {
        return $this->belongsToMany(User::class, 'team_members')
            ->withTimestamps();
    }
}
