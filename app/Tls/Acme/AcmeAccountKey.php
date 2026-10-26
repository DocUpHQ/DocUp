<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls\Acme;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Credentials\EnvelopeCipher;
use App\Credentials\SealedSecret;
use App\Models\AcmeAccount;
use App\Tls\CertificateRefused;
use App\Tls\CertificateRejection;
use App\Tls\Csr;

/**
 * The only class that may open an ACME account key (§8.10.15).
 *
 * > "All certificate private keys and ACME account keys MUST be stored with
 * > authenticated encryption, excluded from every API response and log, and
 * > every read of key material MUST be audited."
 *
 * 🛑 The audit event is the point. An ACME account key can revoke every
 * certificate the account ever issued, so "who read it, and when" is the
 * first question of any incident. Putting the read behind one class with the
 * audit write inside it is the same arrangement `CredentialVault` uses for
 * repository credentials, for the same reason: an accessor on the model
 * would be reachable from any `->account->...` chain, and none of those
 * call sites would write the event.
 */
final readonly class AcmeAccountKey
{
    public function __construct(private EnvelopeCipher $cipher) {}

    /**
     * Seal a fresh key for a new account.
     *
     * @return array{0: \OpenSSLAsymmetricKey, 1: SealedSecret}
     *
     * @throws CertificateRefused
     */
    public function create(string $accountId): array
    {
        $key = Csr::key();

        $pem = '';

        if (! openssl_pkey_export($key, $pem)) {
            throw CertificateRefused::of(CertificateRejection::KeyUnreadable, 'openssl_pkey_export failed');
        }

        return [$key, $this->cipher->seal(['private_key' => $pem], self::aad($accountId))];
    }

    /**
     * Open an account key, writing §8.10.15's audit event.
     *
     * @throws CertificateRefused
     */
    public function open(AcmeAccount $account): \OpenSSLAsymmetricKey
    {
        $opened = $this->cipher->open($account->sealed(), self::aad($account->id));

        Audit::record(
            action: 'tls.acme_account_key.opened',
            actorType: ActorType::System,
            subjectType: 'acme_account',
            subjectId: $account->id,
            payload: ['label' => $account->label, 'kind' => $account->kind],
        );

        $pem = ($opened['private_key'] ?? null)?->reveal();
        $key = is_string($pem) ? openssl_pkey_get_private($pem) : false;

        if ($key === false) {
            throw CertificateRefused::of(CertificateRejection::KeyUnreadable, 'the sealed account key did not parse');
        }

        return $key;
    }

    /**
     * 🛑 The additional authenticated data binds the ciphertext to the row it
     * was written for, so a blob moved between rows fails to open rather
     * than opening as somebody else's key. The account id alone is enough —
     * unlike a repository credential there is no tenant to bind, because an
     * ACME account is installation-scoped.
     */
    public static function aad(string $accountId): string
    {
        return 'acme_account|'.$accountId;
    }
}
