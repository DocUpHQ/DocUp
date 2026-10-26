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

/**
 * §8.10.4's organisation-level parent claim (§10.5).
 *
 * > "an organisation-level parent claim (`_docup-challenge.<apex>` TXT),
 * > after which any host under it binds with no further proof and **no other
 * > organisation may bind under it**"
 *
 * Both halves matter and the second is the one with teeth: proving
 * `example.com` does not merely save you a TXT record per subdomain, it
 * **excludes every other tenant** from `*.example.com`. That exclusion is
 * `active_apex`'s unique index, which is NULL until proof lands so a
 * competing pending claim constrains nothing.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $apex
 * @property string $token published in DNS by design
 * @property string $state pending, verified or revoked
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['apex'])]
final class DomainClaim extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @var list<string> */
    protected $guarded = ['id', 'active_apex'];

    /** @var array<string, mixed> */
    protected $attributes = ['state' => 'pending'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'verified_at' => 'datetime:Y-m-d H:i:s.v',
            'last_checked_at' => 'datetime:Y-m-d H:i:s.v',
            'revoked_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    public function isProven(): bool
    {
        return $this->state === 'verified' && $this->verified_at !== null;
    }
}
