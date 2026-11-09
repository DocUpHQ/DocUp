<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Access\BreakGlass;
use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * One activation of §8.12.20's break-glass read override.
 *
 * 🛑 **A record, not a flag.** The row is what makes the override reviewable:
 * the reason is stored beside the project it was used on and the window it was
 * open for, so "who read what, and why" has an answer afterwards. A session
 * flag would satisfy the feature and defeat the requirement.
 *
 * No `$fillable`: {@see BreakGlass} is the only thing that may open one,
 * because that is where §8.12.20's four preconditions are enforced and a second
 * path is a second place to forget them.
 *
 * 🛑 This model is for the **dashboard** side. The serving path reads the table
 * with a raw query and no tenant context, exactly as `ReaderSessions` reads
 * `docs_sessions`, because §8.9.4 gives a documentation request no tenant to
 * declare. (Named in prose rather than with `{@see}`: Pint turns that into an
 * import, and the Laravel architecture preset rightly refuses a model that
 * depends on a service.)
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $project_id
 * @property string $user_id
 * @property string $reason
 * @property Carbon $opened_at
 * @property Carbon $expires_at
 * @property Carbon|null $closed_at
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
final class BreakGlassGrant extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'opened_at' => 'datetime:Y-m-d H:i:s.v',
            'expires_at' => 'datetime:Y-m-d H:i:s.v',
            'closed_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /**
     * Whether this grant is open.
     *
     * 🛑 Closed **and** expiry, because they mean different things to a review:
     * a grant closed deliberately is evidence of discipline and one that ran
     * its full window is not.
     */
    public function isOpen(?int $now = null): bool
    {
        $now = $now ?? time();

        return $this->closed_at === null && $this->expires_at->getTimestamp() > $now;
    }

    /** @return BelongsTo<User, $this> */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /** @return BelongsTo<Project, $this> */
    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class);
    }
}
