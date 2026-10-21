<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Fixtures\Models;

use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

/**
 * @property string $id
 * @property string $label
 * @property-read string|null $uuid
 */
final class SpikeTag extends Model
{
    use HasUuidKey;

    protected $table = 'spike_tags';

    protected $guarded = [];

    /** @return BelongsToMany<SpikeParent, $this> */
    public function parents(): BelongsToMany
    {
        return $this->belongsToMany(SpikeParent::class, 'spike_parent_tag', 'tag_id', 'parent_id');
    }
}
