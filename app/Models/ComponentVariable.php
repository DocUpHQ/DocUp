<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use App\Credentials\EnvelopeCipher;
use App\Credentials\SealedSecret;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * §8.5.25's component-scoped build environment variable.
 *
 * > "🛑 The system MUST support **component-scoped build environment
 * > variables**, because installing a private dependency — a private
 * > package-index token, a licensed theme, a private submodule key — is
 * > otherwise impossible and is the first thing a migrating commercial team
 * > configures."
 *
 * 🛑 **Scoped to the component, never to the project**, and §8.5.25 says why
 * in the same breath: "so that §8.7.10's project-agnostic rule and §8.7.9's
 * content key both stand unchanged". A project-scoped variable would make a
 * shared build's output depend on which project triggered it, and the
 * one-repository-to-many-projects case would quietly stop being sound.
 *
 * 🛑 **`toArray()` is overridden to drop the sealed columns.** §8.5.25:
 * secrets are "never returned by any API or UI". A model that serialises
 * cleanly is a model that eventually gets serialised, and the first place
 * that happens is an error page or a queue payload nobody meant to inspect.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $component_id
 * @property string $name
 * @property bool $is_public
 * @property string|null $public_value
 * @property int|null $envelope_version
 * @property string|null $kek_fingerprint
 * @property string|null $wrapped_key
 * @property string|null $ciphertext
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
final class ComponentVariable extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @var list<string> */
    protected $guarded = ['id'];

    /** 🛑 Never serialised, in any context. See the class comment. */
    protected $hidden = ['wrapped_key', 'ciphertext', 'kek_fingerprint', 'envelope_version'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'is_public' => false,
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'is_public' => 'boolean',
            'envelope_version' => 'integer',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<Component, $this> */
    public function component(): BelongsTo
    {
        return $this->belongsTo(Component::class);
    }

    /** Does this row hold a sealed value at all? */
    public function isSealed(): bool
    {
        return $this->ciphertext !== null && $this->wrapped_key !== null;
    }

    /** The sealed payload, for {@see EnvelopeCipher::open()}. */
    public function sealed(): ?SealedSecret
    {
        if (! $this->isSealed()) {
            return null;
        }

        return new SealedSecret(
            version: (int) $this->envelope_version,
            kekFingerprint: (string) $this->kek_fingerprint,
            wrappedKey: (string) $this->wrapped_key,
            ciphertext: (string) $this->ciphertext,
        );
    }

    /**
     * 🛑 The sealed columns never leave this object.
     *
     * `$hidden` covers `toArray()` and `toJson()`; this override is here so
     * that a future `makeVisible()` somewhere cannot undo it, which is the
     * one thing `$hidden` alone does not prevent.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $attributes = parent::toArray();

        unset($attributes['wrapped_key'], $attributes['ciphertext'], $attributes['kek_fingerprint'], $attributes['envelope_version']);

        return $attributes;
    }
}
