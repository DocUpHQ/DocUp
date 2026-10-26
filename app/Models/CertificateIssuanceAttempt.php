<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * §8.10.13's attempts table, and §8.10.17's only observability (§10.5).
 *
 * 🛑 **A denied permission query writes no row here.** The exit criterion for
 * this phase is "500 bogus SNI handshakes per minute trigger zero ACME
 * attempts", and a row per handshake would turn an unauthenticated TLS
 * handshake into an unauthenticated INSERT — the amplification the permission
 * endpoint exists to prevent. Denials are counted in the limiter and
 * discarded.
 *
 * What lands here is: a permission that was **granted** (rare, budgeted, and
 * the thing that leads to issuance); an issuance this application performed;
 * and a failure §8.10.17's prober found, which is the only way an operator
 * ever learns that the edge's own ACME exchange failed.
 *
 * @property-read string $id
 * @property string $host
 * @property string $registered_domain
 * @property string $source
 * @property string $outcome permitted, issued or failed
 * @property string|null $reason
 * @property string|null $detail
 * @property Carbon $attempted_at
 */
#[Tenancy(TenancyPosture::Installation, because: 'an attempt is recorded on the handshake path, where no tenant is known yet; the budget it feeds (§8.10.13) is per registered domain and therefore crosses organisations')]
#[Fillable(['host', 'registered_domain', 'source', 'outcome', 'reason', 'detail', 'attempted_at'])]
final class CertificateIssuanceAttempt extends Model
{
    use HasUuidKey;

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'attempted_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }
}
