<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\HasUuidKey;
use App\Credentials\SealedSecret;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * The installation's relationship with an ACME certificate authority (§10.5).
 *
 * 🛑 **This model cannot produce a plaintext account key**, for the same
 * reason {@see RepositoryCredential} cannot produce a plaintext token: an
 * accessor that unsealed would be reachable from any `->account->...` chain,
 * and §8.10.15 says every read of key material is audited. Opening the
 * envelope is `App\Tls\Acme\AcmeAccountKey`'s job and only its job.
 *
 * @property-read string $id
 * @property string $label
 * @property string $kind public or internal (§8.10.14)
 * @property string $directory_url
 * @property string|null $contact
 * @property string|null $account_url the ACME `kid`, set once registered
 * @property int $envelope_version
 * @property string $kek_fingerprint
 * @property string $wrapped_key
 * @property string $ciphertext
 * @property string $state
 * @property Carbon|null $registered_at
 */
#[Tenancy(TenancyPosture::Installation, because: 'an ACME account is the installation\'s relationship with a CA; §8.10.10\'s ceiling is global across accounts, so one per tenant would buy nothing and multiply the key material §8.10.15 must protect')]
#[Fillable(['label', 'kind', 'directory_url', 'contact'])]
final class AcmeAccount extends Model
{
    use HasUuidKey;

    /** @var list<string> */
    protected $guarded = ['id'];

    /**
     * 🛑 Ciphertext in an Inertia prop or a `dd()` is a gift to an offline
     * attacker, and there is no reason to ship it.
     *
     * @var list<string>
     */
    protected $hidden = ['envelope_version', 'kek_fingerprint', 'wrapped_key', 'ciphertext'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'kind' => 'public',
        'state' => 'pending',
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'envelope_version' => 'integer',
            'registered_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** The sealed account key, for the one class permitted to open it. */
    public function sealed(): SealedSecret
    {
        return new SealedSecret(
            $this->envelope_version,
            $this->kek_fingerprint,
            $this->wrapped_key,
            $this->ciphertext,
        );
    }

    public function isRegistered(): bool
    {
        return $this->state === 'registered' && $this->account_url !== null;
    }
}
