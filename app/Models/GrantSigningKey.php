<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\HasUuidKey;
use App\Credentials\SealedSecret;
use App\Readers\Grants\GrantKeys;
use App\Readers\Grants\KeyState;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * One Ed25519 keypair from §8.12.11, in one of {@see KeyState}'s four states.
 *
 * 🛑 **This model cannot produce a plaintext private key**, exactly as
 * {@see Certificate} cannot. `public_key` is published at the JWKS endpoint and
 * is readable here; the private half is sealed, and
 * {@see GrantKeys} is the only class that opens it. §8.12.11
 * is explicit about what that key is worth:
 *
 * > "an edge-held HMAC key makes **every edge node a minter**, so compromising
 * > one proxy forges access to every private project."
 *
 * The asymmetric design means the key never has to travel. This model is the
 * reason it never does.
 *
 * 🛑 **No `organisation_id`.** §8.12.11 puts the public keys at one JWKS
 * endpoint and §15's backup set names "the Ed25519 grant keypair" in the
 * singular. A per-tenant key would publish the installation's tenant list at a
 * public URL, and would mean a reader's grant named their organisation in its
 * `kid`.
 *
 * @property-read string $id
 * @property string $kid
 * @property KeyState $state
 * @property int|null $active_marker generated; the application never writes it
 * @property string $public_key raw 32 bytes
 * @property int $envelope_version
 * @property string $kek_fingerprint
 * @property string $wrapped_key
 * @property string $ciphertext
 * @property Carbon|null $activated_at
 * @property Carbon|null $retiring_at
 * @property Carbon|null $retired_at
 */
#[Tenancy(TenancyPosture::Installation, because: 'the grant keypair is the installation\'s: §8.12.11 publishes one JWKS document, and a per-tenant key would publish the tenant list at a public URL')]
final class GrantSigningKey extends Model
{
    use HasUuidKey;

    /** @var list<string> */
    protected $guarded = ['*'];

    /** @var list<string> */
    protected $hidden = ['envelope_version', 'kek_fingerprint', 'wrapped_key', 'ciphertext'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'state' => KeyState::class,
            'envelope_version' => 'integer',
            'activated_at' => 'datetime:Y-m-d H:i:s.v',
            'retiring_at' => 'datetime:Y-m-d H:i:s.v',
            'retired_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** The sealed private key, for the one class permitted to open it. */
    public function sealed(): SealedSecret
    {
        return new SealedSecret(
            $this->envelope_version,
            $this->kek_fingerprint,
            $this->wrapped_key,
            $this->ciphertext,
        );
    }
}
