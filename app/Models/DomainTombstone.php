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
 * 🛑 §8.10.9's ninety-day hold on a released hostname (§10.5).
 *
 * > "A released hostname MUST enter a **90-day tombstone**, reclaimable only
 * > by the previous owning organisation and always with a freshly issued
 * > token. A dangling CNAME pointing at the installation is otherwise a
 * > cross-tenant takeover."
 *
 * The attack it closes is quiet. An organisation stops using
 * `docs.acme.example`, deletes the domain here, and leaves the CNAME in
 * place — as everybody does. Without the tombstone, anybody may now claim
 * that hostname on this installation, and the CNAME routes Acme's readers to
 * them, under Acme's name, over a certificate the installation issues
 * happily.
 *
 * 🛑 **Not organisation-scoped**, and that is the point: the question this
 * row answers is "may *this other* organisation claim the host?", which a
 * tenancy scope would hide the row from. The `organisation_id` column names
 * the only tenant who may reclaim, which is the opposite of a scope.
 *
 * @property-read string $id
 * @property string $organisation_id the only organisation that may reclaim
 * @property string $host
 * @property Carbon|null $released_at
 * @property Carbon|null $expires_at
 */
#[Tenancy(
    TenancyPosture::Installation,
    because: '🛑 §8.10.9: a tombstone exists to block a DIFFERENT organisation from claiming the '
        .'hostname, so a tenancy scope would hide it from the only reader who matters. The '
        .'organisation_id column names who may reclaim, which is the opposite of a scope.',
)]
#[Fillable([])]
final class DomainTombstone extends Model
{
    use HasUuidKey;

    /** §8.10.9's window. */
    public const DAYS = 90;

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'released_at' => 'datetime:Y-m-d H:i:s.v',
            'expires_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    public function hasLapsed(): bool
    {
        return $this->expires_at !== null && $this->expires_at->isPast();
    }
}
