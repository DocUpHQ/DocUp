<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\HasUuidKey;
use App\Credentials\SealedSecret;
use App\Tls\CertificateSourceKind;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * One certificate from one of §8.10.14's four sources (§10.5).
 *
 * 🛑 `active_host` is a STORED generated column and the application never
 * writes it: NULL unless `state = 'active'`, and under a unique index. A host
 * has at most one certificate a handshake will serve, and the database is
 * where that is true rather than wherever the last writer remembered to
 * supersede the previous row.
 *
 * 🛑 **This model cannot produce a plaintext private key.** `chain_pem` is
 * public — every client receives it — and is readable here. The key is not:
 * `App\Tls\CertificateStore::pem()` opens it, writes §8.10.15's audit event,
 * and is the only caller.
 *
 * @property-read string $id
 * @property string $host
 * @property CertificateSourceKind $source
 * @property string $state active, superseded or revoked
 * @property string|null $organisation_id
 * @property string|null $domain_id
 * @property string|null $acme_account_id
 * @property string $chain_pem
 * @property int $envelope_version
 * @property string $kek_fingerprint
 * @property string $wrapped_key
 * @property string $ciphertext
 * @property string $serial
 * @property string $issuer
 * @property string $fingerprint
 * @property Carbon $not_before
 * @property Carbon $not_after
 * @property Carbon|null $activated_at
 * @property Carbon|null $superseded_at
 * @property Carbon|null $revoked_at
 */
#[Tenancy(TenancyPosture::Installation, because: 'a certificate is served at handshake time, before any tenant is known; the installation wildcard (§8.10.10) belongs to no organisation at all')]
#[Fillable(['host', 'source'])]
final class Certificate extends Model
{
    use HasUuidKey;

    /** @var list<string> */
    protected $guarded = ['id', 'active_host'];

    /** @var list<string> */
    protected $hidden = ['envelope_version', 'kek_fingerprint', 'wrapped_key', 'ciphertext'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'state' => 'active',
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'source' => CertificateSourceKind::class,
            'envelope_version' => 'integer',
            'not_before' => 'datetime:Y-m-d H:i:s.v',
            'not_after' => 'datetime:Y-m-d H:i:s.v',
            'activated_at' => 'datetime:Y-m-d H:i:s.v',
            'superseded_at' => 'datetime:Y-m-d H:i:s.v',
            'revoked_at' => 'datetime:Y-m-d H:i:s.v',
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

    public function isActive(): bool
    {
        return $this->state === 'active';
    }
}
