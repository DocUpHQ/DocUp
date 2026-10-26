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
 * §8.10.13's per-registered-domain budget, as a token bucket (§10.5).
 *
 * 🛑 Keyed on the **registrable** domain and not the hostname, because that is
 * what the CA counts. A budget per host would report 49 remaining to each of
 * fifty subdomains that between them had exhausted one bucket.
 *
 * @property-read string $id
 * @property string $registered_domain
 * @property string $tokens a decimal string; MySQL DECIMAL does not round-trip through float
 * @property Carbon $tokens_at
 * @property Carbon|null $warned_at
 * @property Carbon|null $blocked_at
 */
#[Tenancy(TenancyPosture::Installation, because: 'a registrable domain can carry hostnames belonging to several organisations, and the CA counts them together whether DocUp does or not')]
#[Fillable(['registered_domain', 'tokens', 'tokens_at'])]
final class IssuanceBudget extends Model
{
    use HasUuidKey;

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'tokens_at' => 'datetime:Y-m-d H:i:s.v',
            'warned_at' => 'datetime:Y-m-d H:i:s.v',
            'blocked_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }
}
