<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Credentials;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Models\RepositoryCredential;
use App\Source\Provider;
use App\Support\Uuid;

/**
 * The only thing that seals and opens a provider credential (§8.3.3, §9.1.7).
 *
 * 🛑 **There is no `reveal()` on the model.** §8.3.3 requires that a
 * credential is "never returned in any API or UI response", and the way to
 * make that structural rather than disciplinary is for the unsealing code to
 * exist in exactly one class that writes an audit event every time it runs.
 * A model accessor would be reachable from a Blade template.
 *
 * 🛑 **`rotate()` cannot read.** §9.1.7: "`installation_security_admin` may
 * rotate but never read." Rotation calls {@see EnvelopeCipher::rewrap()},
 * which unwraps the *data key* and rewraps it under the current KEK without
 * touching the payload. The capability to read is absent from that path, not
 * merely unused — which is a property a reviewer can check from the call
 * graph rather than from a promise.
 */
final readonly class CredentialVault
{
    public function __construct(private EnvelopeCipher $cipher) {}

    /**
     * Seal a new credential.
     *
     * @param  array<string, string>  $payload  the secret fields; see {@see CredentialKind::requiredFields()}
     * @param  string|null  $publicMaterial  a deploy key's public half, which is not secret
     *
     * @throws \InvalidArgumentException when the payload does not match the kind
     */
    public function store(
        string $organisationId,
        CredentialKind $kind,
        Provider $provider,
        string $providerHost,
        string $displayName,
        array $payload,
        ?string $publicMaterial = null,
    ): RepositoryCredential {
        $this->assertPayloadMatches($kind, $payload);

        $credential = new RepositoryCredential;
        $credential->organisation_id = $organisationId;
        $credential->kind = $kind;
        $credential->provider = $provider;
        $credential->provider_host = strtolower($providerHost);
        $credential->display_name = $displayName;
        $credential->public_material = $publicMaterial;

        /*
         * 🛑 The AAD binds the ciphertext to this row's identity, so the id
         * must exist **before** the seal. `HasUuidKey` would otherwise assign
         * it on `creating`, which is after. The ordering is load-bearing:
         * sealing first produces an envelope bound to an empty identity, which
         * both fails to open after a reload and — far worse — makes every
         * record's AAD identical, so a ciphertext can be moved between rows.
         * `RepositoryCredential::aad()` now refuses an empty identity for
         * exactly that reason.
         */
        $credential->setAttribute($credential->getKeyName(), Uuid::v7());

        $credential->applySealed($this->cipher->seal($payload, $credential->aad()));
        $credential->save();

        Audit::record(
            action: 'credential.stored',
            actorType: ActorType::User,
            organisationId: $organisationId,
            subjectType: 'repository_credential',
            subjectId: $credential->id,
            payload: [
                // 🛑 §8.22.5: identifiers and codes only. The kind and the host
                // are what an auditor needs; nothing here is the credential, a
                // fingerprint of it, or anything erasure would have to remove.
                'kind' => $kind->value,
                'provider' => $provider->value,
                'envelope_version' => EnvelopeCipher::VERSION,
            ],
        );

        return $credential;
    }

    /**
     * Open a credential for use.
     *
     * Every call is audited, because a credential being read is the event an
     * investigation starts from. The returned values are {@see SecretString},
     * which is what registers them with the §8.5.21 log scrubber — so a
     * credential that escapes into a log line through some path this class
     * does not control is still redacted on the way out.
     *
     * @return array<string, SecretString>
     */
    public function open(RepositoryCredential $credential): array
    {
        $opened = $this->cipher->open($credential->sealed(), $credential->aad());

        $credential->forceFill(['last_used_at' => now()])->saveQuietly();

        Audit::record(
            action: 'credential.opened',
            actorType: ActorType::System,
            organisationId: $credential->organisation_id,
            subjectType: 'repository_credential',
            subjectId: $credential->id,
            payload: ['kind' => $credential->kind->value],
        );

        return $opened;
    }

    /**
     * Rewrap a credential under the current KEK, without reading it.
     *
     * Returns false when the record is already current, so a rotation sweep
     * can report how much work it actually did rather than how many rows it
     * looked at.
     */
    public function rotate(RepositoryCredential $credential): bool
    {
        if ($credential->kek_fingerprint === $this->cipher->currentFingerprint()) {
            return false;
        }

        $credential->applySealed($this->cipher->rewrap($credential->sealed(), $credential->aad()));
        $credential->rotated_at = now();
        $credential->save();

        Audit::record(
            action: 'credential.rotated',
            actorType: ActorType::User,
            organisationId: $credential->organisation_id,
            subjectType: 'repository_credential',
            subjectId: $credential->id,
            payload: ['kek_fingerprint' => $credential->kek_fingerprint],
        );

        return true;
    }

    /**
     * @param  array<string, string>  $payload
     *
     * @throws \InvalidArgumentException
     */
    private function assertPayloadMatches(CredentialKind $kind, array $payload): void
    {
        $missing = array_diff($kind->requiredFields(), array_keys($payload));

        if ($missing !== []) {
            throw new \InvalidArgumentException(
                $kind->value.' is missing required fields: '.implode(', ', $missing),
            );
        }

        $unknown = array_diff(array_keys($payload), $kind->requiredFields(), $kind->optionalFields());

        if ($unknown !== []) {
            /*
             * Refused rather than ignored. An unknown field is either a typo —
             * in which case the required field it was meant to be is missing
             * and the credential silently will not work — or somebody storing
             * something in the envelope that the rest of the system does not
             * know is there.
             */
            throw new \InvalidArgumentException(
                $kind->value.' does not accept these fields: '.implode(', ', $unknown),
            );
        }
    }
}
