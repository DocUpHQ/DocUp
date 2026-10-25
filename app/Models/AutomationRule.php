<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Automation\AutomationAction;
use App\Automation\AutomationTrigger;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * One §8.6.8 automation rule.
 *
 * > "The system MUST support automation rules triggered by version
 * > **creation or disappearance**: activate, hide, make public or private,
 * > set as default, or trigger a build — filtered by branch/tag regex,
 * > changed-path globs, commit message or PR label. 🛑 These rules are the
 * > mechanism that makes a monorepo feeding N projects tractable."
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $project_id
 * @property int $position
 * @property string $label
 * @property AutomationTrigger $trigger
 * @property string $ref_kind
 * @property string|null $ref_pattern
 * @property list<string>|null $path_globs
 * @property string|null $commit_message_pattern
 * @property string|null $pr_label
 * @property AutomationAction $action
 * @property bool $enabled
 * @property bool $continue_matching
 * @property Carbon|null $last_fired_at
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable([
    'position', 'label', 'trigger', 'ref_kind', 'ref_pattern', 'path_globs',
    'commit_message_pattern', 'pr_label', 'action', 'enabled', 'continue_matching',
])]
final class AutomationRule extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @var array<string, mixed> */
    protected $attributes = [
        'ref_kind' => 'any',
        'enabled' => true,
        'continue_matching' => false,
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'trigger' => AutomationTrigger::class,
            'action' => AutomationAction::class,
            'path_globs' => 'array',
            'enabled' => 'boolean',
            'continue_matching' => 'boolean',
            'last_fired_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<Project, $this> */
    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class);
    }

    /**
     * 🛑 §8.6.15's pairing, checked before a row is written.
     *
     * A `delete_version` rule on `version_created` would never fire, and a
     * rule that silently never fires is worse than one refused on save: the
     * operator believes their tidy-up is configured.
     */
    public function actionSuitsTrigger(): bool
    {
        return $this->action->isValidFor($this->trigger);
    }
}
