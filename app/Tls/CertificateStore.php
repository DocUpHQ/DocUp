<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Credentials\EnvelopeCipher;
use App\Models\Certificate;
use App\Models\Domain;
use Illuminate\Support\Facades\DB;

/**
 * §8.10.14's database-served certificate store.
 *
 * > "🛑 Uploaded and internal-PKI certificates MUST be delivered to the edge
 * > **at handshake time from the database**, not by writing files or calling
 * > a proxy admin API, so they replicate to every replica with no shared
 * > storage. The proxy admin API MUST stay **disabled** — it is
 * > root-equivalent on the edge."
 *
 * 🛑 That requirement is also §15.5's multi-replica answer, and §19 decision
 * 12 says so outright: there is no maintained first-party SQL certificate
 * store for the edge, so "the database is the store" is how a second replica
 * serves the same certificate with no shared volume. Writing PEM files to
 * disk would work on one node and silently stop working on two.
 *
 * 🛑 `pem()` is the only reader of key material and writes §8.10.15's audit
 * event. Everything else here handles the chain, which is public.
 */
final readonly class CertificateStore
{
    public function __construct(private EnvelopeCipher $cipher) {}

    /** The certificate a handshake for this hostname should present, if any. */
    public function activeFor(string $host): ?Certificate
    {
        return Certificate::query()->where('active_host', $host)->first();
    }

    /**
     * Record a newly issued certificate and make it the active one.
     *
     * 🛑 One transaction, and the supersede comes first. `active_host` is
     * generated from `state` under a unique index, so inserting the new row
     * while the old one is still active is rejected by the database — which
     * is the behaviour wanted, but only if the two statements cannot be
     * separated by a crash. Reversed, a crash between them leaves a host
     * with no certificate at all.
     */
    public function store(
        string $host,
        IssuedCertificate $certificate,
        CertificateSourceKind $source,
        ?Domain $domain = null,
        ?string $acmeAccountId = null,
    ): Certificate {
        if (! $certificate->covers($host)) {
            throw CertificateRefused::of(
                CertificateRejection::HostNotCovered,
                $host.' is not among '.implode(', ', $certificate->names),
            );
        }

        $sealed = $this->cipher->seal(
            ['private_key' => $certificate->privateKeyPem],
            self::aad($host, $certificate->fingerprint),
        );

        return DB::transaction(function () use ($host, $certificate, $source, $domain, $acmeAccountId, $sealed): Certificate {
            Certificate::query()
                ->where('active_host', $host)
                ->update(['state' => 'superseded', 'superseded_at' => now()]);

            $stored = new Certificate;

            $stored->forceFill([
                'host' => $host,
                'source' => $source,
                'state' => 'active',
                'organisation_id' => $domain?->organisation_id,
                'domain_id' => $domain?->id,
                'acme_account_id' => $acmeAccountId,
                'chain_pem' => $certificate->chainPem,
                'envelope_version' => $sealed->version,
                'kek_fingerprint' => $sealed->kekFingerprint,
                'wrapped_key' => $sealed->wrappedKey,
                'ciphertext' => $sealed->ciphertext,
                'serial' => $certificate->serial,
                'issuer' => $certificate->issuer,
                'fingerprint' => $certificate->fingerprint,
                'not_before' => $certificate->notBefore,
                'not_after' => $certificate->notAfter,
                'activated_at' => now(),
            ])->save();

            Audit::record(
                action: 'tls.certificate.stored',
                actorType: ActorType::System,
                organisationId: $domain?->organisation_id,
                subjectType: 'certificate',
                subjectId: $stored->id,
                payload: [
                    'source' => $source->value,
                    'fingerprint' => $certificate->fingerprint,
                    'not_after' => $certificate->notAfter->toDateTimeString(),
                ],
            );

            return $stored;
        });
    }

    /**
     * The chain and key, concatenated as the edge's certificate endpoint
     * must return them — and §8.10.15's audit event.
     *
     * 🛑 Every call writes an audit row, on the handshake path. That sounds
     * expensive and is the requirement: "every read of key material MUST be
     * audited". It is affordable because this path is not hot — the proxy
     * caches a certificate it has fetched for the life of the certificate,
     * so this runs once per host per issuance, not once per connection. If
     * that ever stops being true the answer is a cache in front of the
     * endpoint, never a quieter audit.
     */
    public function pem(Certificate $certificate): string
    {
        $opened = $this->cipher->open(
            $certificate->sealed(),
            self::aad($certificate->host, $certificate->fingerprint),
        );

        Audit::record(
            action: 'tls.certificate_key.read',
            actorType: ActorType::System,
            organisationId: $certificate->organisation_id,
            subjectType: 'certificate',
            subjectId: $certificate->id,
            payload: ['fingerprint' => $certificate->fingerprint],
        );

        $key = ($opened['private_key'] ?? null)?->reveal();

        if (! is_string($key) || $key === '') {
            throw CertificateRefused::of(CertificateRejection::KeyUnreadable, 'the sealed key did not open');
        }

        return rtrim($certificate->chain_pem, "\n")."\n".rtrim($key, "\n")."\n";
    }

    /** Withdraw a certificate from service without destroying the evidence. */
    public function revoke(Certificate $certificate, string $reason): void
    {
        $certificate->forceFill(['state' => 'revoked', 'revoked_at' => now()])->save();

        Audit::record(
            action: 'tls.certificate.revoked',
            actorType: ActorType::System,
            organisationId: $certificate->organisation_id,
            subjectType: 'certificate',
            subjectId: $certificate->id,
            payload: ['reason' => $reason],
        );
    }

    /**
     * 🛑 The AAD binds the sealed key to **both** the hostname and the leaf's
     * fingerprint.
     *
     * The hostname alone would let a ciphertext be moved between two
     * certificates for one host — a renewal and its predecessor — and open
     * cleanly, producing a chain and a key that do not match. That failure
     * appears only at handshake, on the live hostname, with every row in the
     * database looking correct.
     */
    public static function aad(string $host, string $fingerprint): string
    {
        return 'certificate|'.$host.'|'.$fingerprint;
    }
}
