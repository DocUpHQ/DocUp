<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Fixtures\Models;

use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * @property string $id
 * @property string $parent_id
 * @property string $name
 * @property-read string|null $uuid
 */
final class SpikeChild extends Model
{
    use HasUuidKey;

    protected $table = 'spike_children';

    protected $guarded = [];

    /** @return BelongsTo<SpikeParent, $this> */
    public function parent(): BelongsTo
    {
        return $this->belongsTo(SpikeParent::class, 'parent_id');
    }
}
