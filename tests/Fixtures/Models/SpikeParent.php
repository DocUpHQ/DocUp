<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Fixtures\Models;

use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * A test-only model exercising the SPEC 9.1 identifier policy.
 *
 * Phase 01's scope note is explicit that no domain model exists yet - no
 * organisations, no projects. But the exit criteria require proving that
 * route binding 404s and that belongsToMany works across a BINARY(16) pivot,
 * and proving that needs models. So these live in tests/Fixtures and their
 * tables are created by the test, never by a migration.
 *
 * The shape deliberately mirrors the relation that ADR 0006 measured breaking:
 * project_versions <-> components through component_mounts (SPEC 8.7.2). If the
 * key layer regresses, it regresses here first and loudly, instead of in Phase
 * 13 as a silently empty composition.
 */
/**
 * @property string $id
 * @property string $name
 * @property-read string|null $uuid
 */
final class SpikeParent extends Model
{
    use HasUuidKey;

    protected $table = 'spike_parents';

    protected $guarded = [];

    /** @return HasMany<SpikeChild, $this> */
    public function children(): HasMany
    {
        return $this->hasMany(SpikeChild::class, 'parent_id');
    }

    /**
     * The relation ADR 0006 found returning silently empty under a cast key.
     *
     * @return BelongsToMany<SpikeTag, $this>
     */
    public function tags(): BelongsToMany
    {
        return $this->belongsToMany(SpikeTag::class, 'spike_parent_tag', 'parent_id', 'tag_id')
            ->withPivot('note');
    }
}
