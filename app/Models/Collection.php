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
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * §8.2.5's collection: a grouping of projects for presentation (§10.1).
 *
 * 🛑 **No access column, deliberately.** §8.2.5: "A collection is a *hosting
 * and presentation* construct; its effect on access is only the intersection
 * rule in §8.12.8. It is never a separate authorisation primitive." There is
 * therefore nothing on this model a reader decision could consult, which is
 * the point — see the migration for why the obvious convenience column would
 * be the widening flag §8.12.8 forbids.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string|null $parent_project_id raw 16 bytes; §8.21.2's URL parent
 * @property string $slug
 * @property string $name
 * @property string $prefix_convention §8.2.6; `projects` or `alias`
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['slug', 'name', 'prefix_convention'])]
final class Collection extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** §8.2.6's `/projects/<alias>/`, as the literal it actually is. */
    public const PROJECTS_SEGMENT = 'projects';

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'prefix_convention' => 'projects',
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<Project, $this> */
    public function parentProject(): BelongsTo
    {
        return $this->belongsTo(Project::class, 'parent_project_id');
    }

    /** @return HasMany<CollectionProject, $this> */
    public function members(): HasMany
    {
        return $this->hasMany(CollectionProject::class)->orderBy('position')->orderBy('alias');
    }

    /**
     * The path segments a member's alias hangs under, relative to the parent's
     * own mount.
     *
     * §8.2.6 requires `/projects/<alias>/` to be "a supported prefix
     * convention", not the only one — so the convention is a column and this
     * is the one place it turns into a path. Two call sites reading the column
     * and joining segments themselves is how the mount and the generated
     * redirect come to disagree about where a member lives.
     *
     * @return list<string>
     */
    public function prefixSegments(): array
    {
        return $this->prefix_convention === 'projects' ? [self::PROJECTS_SEGMENT] : [];
    }
}
