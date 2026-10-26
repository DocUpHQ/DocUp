<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

use App\Egress\HardenedEgressClient;
use App\Models\AcmeAccount;
use App\Tls\Acme\AcmeAccountKey;
use App\Tls\Acme\AcmeChallenges;
use App\Tls\Acme\AcmeClient;
use App\Tls\Acme\Jws;

/**
 * §8.10.14's first two sources, which are one implementation.
 *
 * 🛑 **Public ACME and an internal ACME directory differ by a URL.** They
 * speak the same protocol to the same client with the same account shape;
 * what differs is which certificate authority answers and whether anybody
 * outside the building trusts it. Writing them as two classes would have
 * produced two copies of RFC 8555 that drift, and would have implied a
 * difference in the protocol that does not exist.
 *
 * The distinction that *is* real is recorded on the row: `acme_accounts.kind`
 * and `certificates.source`, so an operator auditing what is serving can tell
 * a Let's Encrypt certificate from a step-ca one without inspecting a chain.
 *
 * 🛑 This source is **not** how a custom domain normally gets a public
 * certificate. §8.10.11's design has the proxy obtain that one on demand,
 * gated by the permission endpoint, which is why "no row in `certificates`"
 * is a valid and common state for a live hostname. This class exists for the
 * air-gapped case, for an operator who would rather the application held the
 * key, and for §8.10.10's wildcard where the proxy has no SNI to work from.
 */
final readonly class AcmeCertificateSource implements CertificateSource
{
    public function __construct(
        private AcmeAccount $account,
        private AcmeAccountKey $keys,
        private HardenedEgressClient $egress,
        private AcmeChallenges $challenges,
    ) {}

    public function kind(): CertificateSourceKind
    {
        return $this->account->kind === 'internal'
            ? CertificateSourceKind::InternalAcme
            : CertificateSourceKind::PublicAcme;
    }

    /**
     * Register this account with its directory, if it is not already.
     *
     * Separated from `issue()` because registration is an operator action
     * with its own audit trail and its own failure — a wrong directory URL
     * or an unaccepted terms-of-service is a configuration problem, and
     * discovering it during the first reader's handshake is too late.
     *
     * @throws CertificateRefused
     */
    public function register(): AcmeAccount
    {
        if ($this->account->isRegistered()) {
            return $this->account;
        }

        $client = $this->client();

        $accountUrl = $client->register($this->account->contact);

        $this->account->forceFill([
            'account_url' => $accountUrl,
            'state' => 'registered',
            'registered_at' => now(),
        ])->save();

        return $this->account;
    }

    public function issue(string $host): IssuedCertificate
    {
        if (! $this->account->isRegistered()) {
            throw CertificateRefused::of(
                CertificateRejection::NoAcmeAccount,
                'account "'.$this->account->label.'" is not registered with '.$this->account->directory_url,
            );
        }

        [$chain, $key] = $this->client()->certificate($host);

        return IssuedCertificate::fromPem($chain, $key);
    }

    /** @throws CertificateRefused */
    private function client(): AcmeClient
    {
        return new AcmeClient(
            $this->egress,
            $this->challenges,
            new Jws($this->keys->open($this->account)),
            $this->account->directory_url,
            $this->account->account_url,
        );
    }
}
