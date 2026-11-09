<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * §10.7's `theme_assignments` — a named, reusable binding of a domain mount to
 * a published theme revision.
 *
 * 🛑 **The indirection is the feature.** §10.5 puts `theme_assignment_id` on
 * `domain_mounts`, not `theme_revision_id`, and the reason is that a reseller's
 * twelve white-labelled mounts share one assignment: publishing a new revision
 * moves all twelve without writing to the routing table at all. Twelve mount
 * updates would bump `routing_epoch` and invalidate resolution for a change
 * that altered no routing.
 *
 * 🛑 **`organisation_id` and `scope_id` hold the same value at organisation
 * scope, and that is not redundancy.** MySQL refuses a CASCADE foreign key on
 * the base column of a stored generated column, so the §18.21 sentinel is
 * derived from `scope_id` (no foreign key) while `organisation_id` carries the
 * tenant cascade. The migration records the error that found this.
 *
 * @property-read string $id
 * @property string|null $organisation_id the tenancy key; carries the cascade
 * @property string $scope_type installation or organisation
 * @property string|null $scope_id 🛑 no FK: the sentinel is generated from it
 * @property string $name
 * @property string $theme_revision_id
 * @property string|null $created_by
 */
#[Tenancy(
    TenancyPosture::Installation,
    because: 'An installation-scope assignment — the operator’s own house theme, offered to '
        .'every tenant’s mounts — has a NULL organisation_id, which the global scope would '
        .'filter away precisely when a tenant context is declared. App\\Branding\\Themes '
        .'resolves an assignment by mount and filters by owner explicitly.'
)]
final class ThemeAssignment extends Model
{
    use HasUuidKey;

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<ThemeRevision, $this> */
    public function revision(): BelongsTo
    {
        return $this->belongsTo(ThemeRevision::class, 'theme_revision_id');
    }
}
