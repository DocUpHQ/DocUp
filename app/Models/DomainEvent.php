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
use Illuminate\Support\Carbon;

/**
 * The hash-chained record of a hostname's life (§10.5).
 *
 * 🛑 Chained for the same reason §8.22.5 chains the audit log, applied to a
 * narrower question: these rows are the record of **who was allowed to serve
 * a hostname and when**. A deleted `released` row would make a tombstone
 * look like it never happened, and a reordered pair would make a reclaim
 * look like an original claim — both are exactly the histories somebody
 * would want to rewrite after a takeover.
 *
 * The chain is per organisation and over the previous row's digest.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string|null $domain_id null once the domain is released
 * @property string $host
 * @property string $event
 * @property array<string, mixed>|null $payload
 * @property string $digest raw 32 bytes
 * @property string|null $previous_digest raw 32 bytes
 * @property Carbon|null $occurred_at
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable([])]
final class DomainEvent extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'payload' => 'array',
            'occurred_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }
}
