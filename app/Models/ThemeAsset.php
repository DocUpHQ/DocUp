<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Branding\Assets\AssetIntake;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Model;

/**
 * One row of §10.7's `theme_assets` — a logo, favicon, social card or font that
 * §8.14.11's pipeline has already re-encoded or sanitised.
 *
 * 🛑 **A row exists only for bytes DocUp wrote.** {@see AssetIntake} is the
 * sole writer: it sniffs the upload, re-encodes the raster or sanitises the
 * SVG, hashes **its own output** and then inserts. So there is no state in
 * which this table references bytes that arrived from a tenant unaltered, and
 * `content_hash` is an address for something DocUp produced. A model that could
 * be created directly would make that claim untrue without changing a line of
 * the pipeline.
 *
 * @property-read string $id
 * @property string|null $organisation_id NULL at installation scope
 * @property string $scope_type
 * @property string|null $scope_id
 * @property string $kind logo, favicon, social_card or font
 * @property string $content_hash 🛑 over the bytes DocUp wrote (§8.14.11)
 * @property string $media_type always a type DocUp produced itself
 * @property int $byte_size
 * @property int|null $width
 * @property int|null $height
 * @property string $source_media_type what was sniffed from the upload
 * @property string $label 🛑 the operator's own; the filename is discarded
 * @property string|null $created_by
 */
#[Tenancy(
    TenancyPosture::Installation,
    because: 'An installation-scope asset — the operator’s own logo, served on the credential '
        .'pages §8.14.12 keeps tenant-free — has a NULL organisation_id, which the global '
        .'scope would filter away exactly when a tenant context is declared. '
        .'App\\Branding\\ThemeAssets does the scope filtering, and does it as a widening '
        .'(installation plus the caller’s own organisation) that a global scope cannot express.'
)]
final class ThemeAsset extends Model
{
    use HasUuidKey;

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'byte_size' => 'integer',
            'width' => 'integer',
            'height' => 'integer',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }
}
