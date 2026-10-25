<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use App\Source\Provider;
use App\Webhooks\ProviderProfile;
use App\Webhooks\SignatureScheme;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * One repository's incoming webhook, and the secret that proves a delivery
 * came from it (§8.19.3, §8.3.6).
 *
 * 🛑 **This model cannot produce a plaintext secret**, for the reason
 * {@see RepositoryCredential} gives at greater length: unsealing is
 * `App\Webhooks\IntegrationSecrets`' job, and a model accessor that
 * decrypted would be reachable from any `->integration->...` chain, template
 * included.
 *
 * 🛑 It is also the row that §8.5.4's first deduplication layer points at:
 * `build_requests.integration_id` is a foreign key here, and
 * `UNIQUE (integration_id, delivery_id)` is only a replay defence because
 * one repository has exactly one of these.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $repository_id
 * @property Provider $provider
 * @property SignatureScheme $scheme
 * @property int $envelope_version
 * @property string $kek_fingerprint
 * @property string $wrapped_key
 * @property string $ciphertext
 * @property string $state
 * @property Carbon|null $last_delivery_at
 * @property Carbon|null $rotated_at
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
final class WebhookIntegration extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /**
     * 🛑 Hidden so `toArray()`, `toJson()`, an Inertia prop and a stray
     * `dd()` all omit the envelope. The values are ciphertext, so this is
     * belt and braces — but ciphertext in a UI payload is a gift to an
     * offline attacker and there is no reason to ship it.
     *
     * @var list<string>
     */
    protected $hidden = ['wrapped_key', 'ciphertext', 'kek_fingerprint', 'envelope_version'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'state' => 'active',
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'provider' => Provider::class,
            'scheme' => SignatureScheme::class,
            'last_delivery_at' => 'datetime:Y-m-d H:i:s.v',
            'rotated_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<Repository, $this> */
    public function repository(): BelongsTo
    {
        return $this->belongsTo(Repository::class);
    }

    public function isActive(): bool
    {
        return $this->state === 'active';
    }

    /** Where this provider puts its signature, delivery id and event name. */
    public function profile(): ProviderProfile
    {
        return ProviderProfile::for($this->provider);
    }
}
