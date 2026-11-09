<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Branding\ThemeRevisions;
use App\Concerns\HasUuidKey;
use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;

/**
 * One row of §10.7's `theme_revisions` — a draft or published theme at one
 * cascade rung (§8.14.1, §8.14.6).
 *
 * 🛑 **Nothing here validates, and nothing here publishes.** A revision reaches
 * the database only through {@see ThemeRevisions}, which is where §8.14.2's
 * grammar, §8.14.1's lock check, §8.14.5's contrast gate and the audit event
 * all live. A model that validated in a mutator would be a second place the
 * rules lived, reachable by `create()` from anywhere — and §8.14.5's refusal
 * would then be a refusal that one code path honoured.
 *
 * @property-read string $id
 * @property string|null $organisation_id NULL at installation scope (§12.1)
 * @property string $scope_type
 * @property string|null $scope_id
 * @property int $revision_number
 * @property string $state 🛑 §8.14.6: draft, published or superseded
 * @property array<array-key, mixed> $tokens this level's own values only
 * @property array<array-key, mixed> $locks §8.14.1's per-path locks
 * @property array<array-key, mixed> $chrome 🛑 §8.14.3 structured content, never HTML
 * @property array<array-key, mixed> $email §8.14.13's slot overrides
 * @property string|null $content_hash 🛑 §8.14.4's immutable stylesheet address
 * @property array<array-key, mixed>|null $contrast §8.14.5's report
 * @property string|null $contrast_verdict
 * @property bool $contrast_override 🛑 §8.14.5: audited
 * @property string|null $contrast_override_reason
 * @property CarbonImmutable|null $published_at
 * @property string|null $published_by
 * @property string|null $created_by
 */
#[Tenancy(
    TenancyPosture::Installation,
    because: 'This table holds installation-scope revisions with a NULL organisation_id, and '
        .'the global scope would filter exactly those away — so every tenant would resolve '
        .'a cascade with no root the moment a tenant context was declared, and every theme '
        .'would silently fall back to code defaults. The same shape as role_assignments. '
        .'App\\Branding\\ThemeRevisions filters by scope explicitly and is the only reader.'
)]
final class ThemeRevision extends Model
{
    use HasUuidKey;

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'state' => 'draft',
        'contrast_override' => false,
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'tokens' => 'array',
            'locks' => 'array',
            'chrome' => 'array',
            'email' => 'array',
            'contrast' => 'array',
            'contrast_override' => 'boolean',
            'revision_number' => 'integer',
            'published_at' => 'immutable_datetime:Y-m-d H:i:s.v',
            'created_at' => 'immutable_datetime:Y-m-d H:i:s.v',
            'updated_at' => 'immutable_datetime:Y-m-d H:i:s.v',
        ];
    }

    public function isPublished(): bool
    {
        return $this->state === 'published';
    }
}
