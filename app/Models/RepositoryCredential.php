<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use App\Credentials\CredentialKind;
use App\Credentials\EnvelopeCipher;
use App\Credentials\SealedSecret;
use App\Source\Provider;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;

/**
 * A provider credential at rest (§8.3.3, §9.1.7).
 *
 * 🛑 **This model cannot produce a plaintext credential.** There is no
 * accessor, no `getTokenAttribute`, no `decrypt()`. Opening an envelope is
 * `App\Credentials\CredentialVault`'s job and only its job, because that is
 * where the audit event is written. A model method that unsealed would be
 * reachable from any `->credential->...` chain in the codebase, including from
 * a Blade template, and §8.3.3 says a credential is "never returned in any API
 * or UI response".
 *
 * `$hidden` carries the envelope columns so that `toArray()`, `toJson()`,
 * Inertia props and a `dd()` of a collection all omit them. That is belt and
 * braces — the values are ciphertext — but ciphertext in a UI payload is a
 * gift to an offline attacker and there is no reason to ship it.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property CredentialKind $kind
 * @property Provider $provider
 * @property string $provider_host
 * @property string $display_name
 * @property int $envelope_version
 * @property string $kek_fingerprint
 * @property string $wrapped_key
 * @property string $ciphertext
 * @property string|null $public_material
 * @property Carbon|null $expires_at
 * @property Carbon|null $last_used_at
 * @property Carbon|null $rotated_at
 * @property string $state
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['kind', 'provider', 'provider_host', 'display_name', 'public_material', 'expires_at'])]
final class RepositoryCredential extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @var array<string, mixed> */
    protected $attributes = [
        'state' => 'active',
    ];

    /**
     * 🛑 The envelope never reaches a response body, a log line or a dump.
     *
     * @var list<string>
     */
    protected $hidden = ['wrapped_key', 'ciphertext', 'kek_fingerprint'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'kind' => CredentialKind::class,
            'provider' => Provider::class,
            'expires_at' => 'datetime:Y-m-d H:i:s.v',
            'last_used_at' => 'datetime:Y-m-d H:i:s.v',
            'rotated_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return HasMany<Repository, $this> */
    public function repositories(): HasMany
    {
        return $this->hasMany(Repository::class, 'credential_id');
    }

    /**
     * The sealed envelope, as the cipher wants it.
     *
     * Returns the envelope, never its contents — assembling the value object
     * is not unsealing it, and the vault is still the only thing that holds a
     * key.
     */
    public function sealed(): SealedSecret
    {
        return new SealedSecret(
            version: (int) $this->envelope_version,
            kekFingerprint: (string) $this->kek_fingerprint,
            wrappedKey: (string) $this->wrapped_key,
            ciphertext: (string) $this->ciphertext,
        );
    }

    /** Write a sealed envelope back onto the record. */
    public function applySealed(SealedSecret $sealed): void
    {
        $this->envelope_version = $sealed->version;
        $this->kek_fingerprint = $sealed->kekFingerprint;
        $this->wrapped_key = $sealed->wrappedKey;
        $this->ciphertext = $sealed->ciphertext;
    }

    /**
     * The AAD binding this record's ciphertext to this record (§9.1.7).
     *
     * 🛑 Read from the **current** attributes, not from `getRawOriginal()`.
     * The first version used `getRawOriginal`, which is empty on a model that
     * has not been saved yet — and sealing happens before the insert, because
     * the AAD needs the id. Every credential therefore sealed under an AAD of
     * two empty strings: identical for every record, so a ciphertext could be
     * moved between rows and would decrypt perfectly, and a record reloaded
     * with `fresh()` could not be opened at all. Both halves were caught by
     * `EnvelopeEncryptionTest` on its first run.
     *
     * The emptiness check is what makes the mistake unrepeatable: an AAD that
     * does not bind is worse than no AAD, because the schema then claims a
     * guarantee the data does not support.
     */
    public function aad(): string
    {
        $attributes = $this->getAttributes();

        $id = is_string($attributes['id'] ?? null) ? (string) $attributes['id'] : '';
        $organisationId = is_string($attributes['organisation_id'] ?? null)
            ? (string) $attributes['organisation_id']
            : '';

        if ($id === '' || $organisationId === '') {
            throw new \LogicException(
                'a credential cannot be sealed before its id and organisation are set: the AAD would not bind (§9.1.7)',
            );
        }

        return EnvelopeCipher::aad($id, $organisationId, $this->kind);
    }
}
