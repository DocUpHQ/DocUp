<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Branding\TokenRegistry;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Model;

/**
 * One row of §10.7's `token_definitions` — the §8.14.1 registry, materialised.
 *
 * 🛑 **Not the authority.** {@see TokenRegistry} validates; this table records
 * what the installation defines so a query, `docup:doctor` and the dashboard
 * can read it without booting every plugin. The migration that creates the
 * table says why at length. Nothing reads a default from here.
 *
 * @property-read string $id
 * @property string $name
 * @property string $type
 * @property string $token_group
 * @property string $default_value
 * @property string|null $dark_value 🛑 NULL means one value in both schemes (§8.14.7)
 * @property string $deepest_level
 * @property array<array-key, mixed> $options
 * @property string $minimum
 * @property string $maximum
 * @property int $max_length
 * @property string|null $asset_kind
 * @property string $purpose
 * @property string $source core or plugin
 */
#[Tenancy(
    TenancyPosture::Installation,
    because: 'A token definition is a fact about the software, not about a customer: every '
        .'tenant sees the same forty-five tokens, and the table has no organisation_id to '
        .'scope by. §8.14.1 makes the registry plugin-extendable, so what varies between '
        .'installations is which plugins are present, never which tenant is asking.'
)]
final class TokenDefinition extends Model
{
    use HasUuidKey;

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'options' => 'array',
            'max_length' => 'integer',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }
}
