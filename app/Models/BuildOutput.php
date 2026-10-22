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

/**
 * One format's stored tree for one build (§10.3).
 *
 * 🛑 `storage_key` carries §8.8.1's grammar — `builds/{build_id}/{media_type}`
 * and nothing else. An architecture test proves exactly one expression in the
 * tree builds that prefix, because a slug in a storage key only hurts the first
 * time somebody renames a project, by which point every stored artifact is
 * unreachable.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $build_id
 * @property string $format
 * @property string $storage_key
 * @property int $file_count
 * @property int $total_bytes
 * @property string|null $content_sha256
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['format', 'storage_key', 'file_count', 'total_bytes', 'content_sha256'])]
final class BuildOutput extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'file_count' => 'integer',
            'total_bytes' => 'integer',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<Build, $this> */
    public function build(): BelongsTo
    {
        return $this->belongsTo(Build::class);
    }
}
