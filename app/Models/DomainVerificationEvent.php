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
 * One §8.10.6 check, append-only and retained 400 days (§10.5).
 *
 * 🛑 `observed` carries what each resolver actually said, which is the
 * difference between a record somebody can act on and one that says only
 * "failed". An operator whose domain stopped verifying needs to know whether
 * the record was absent, wrong, or seen by one resolver and not the other —
 * and if the row does not say, they will run `dig` and find today's answer
 * rather than the one that failed at 03:00.
 *
 * @property-read string $id
 * @property string $domain_id
 * @property string $method parent_claim, dns_txt or cname
 * @property string $outcome passed, failed, disagreed or unresolvable
 * @property array<string, mixed>|null $observed
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable([])]
final class DomainVerificationEvent extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** §8.10.6's retention. */
    public const RETENTION_DAYS = 400;

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'observed' => 'array',
            'checked_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }
}
