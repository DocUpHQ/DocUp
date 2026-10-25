<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Builds\SkipEffect;
use App\Builds\SkipRuleKind;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * One §8.5.4 pre-dispatch skip rule.
 *
 * Ordered by `position`, first match wins, evaluated before a build request
 * is dispatched — "pre-dispatch" in the requirement is not decoration, it is
 * the difference between a `skipped` request and a build that starts and is
 * then thrown away.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $project_id
 * @property int $position
 * @property string $label
 * @property SkipRuleKind $kind
 * @property string|null $pattern
 * @property list<string>|null $path_globs
 * @property SkipEffect $effect
 * @property bool $enabled
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['position', 'label', 'kind', 'pattern', 'path_globs', 'effect', 'enabled'])]
final class BuildSkipRule extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @var array<string, mixed> */
    protected $attributes = [
        'enabled' => true,
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'kind' => SkipRuleKind::class,
            'effect' => SkipEffect::class,
            'path_globs' => 'array',
            'enabled' => 'boolean',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<Project, $this> */
    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class);
    }
}
