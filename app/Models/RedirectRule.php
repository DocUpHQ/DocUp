<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use App\Redirects\RedirectKind;
use App\Redirects\Redirects;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;

/**
 * One §8.11.2 redirect rule (§10.5).
 *
 * 🛑 Nothing here validates. A rule reaches the database only through
 * {@see Redirects}, which is where §8.11.2's target rule,
 * §8.11.3's cycle detection and §8.11.4's regex containment all live — and
 * where the audit event is written. A model that validated in a mutator
 * would be a second place the rules lived, reachable by `create()` from
 * anywhere, and the one that got forgotten.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $project_id
 * @property int $position 🛑 §8.11.2 explicit ordering, never a heuristic
 * @property RedirectKind $kind
 * @property bool $forced 🛑 §8.11.1: before the existence probe, or after
 * @property string $from_pattern
 * @property string $to_target
 * @property int $status 301, 302, 307 or 308
 * @property bool $enabled
 * @property string|null $description
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['position', 'kind', 'forced', 'from_pattern', 'to_target', 'status', 'enabled', 'description'])]
final class RedirectRule extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'forced' => false,
        'status' => 301,
        'enabled' => true,
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'kind' => RedirectKind::class,
            'position' => 'integer',
            'status' => 'integer',
            'forced' => 'boolean',
            'enabled' => 'boolean',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }
}
