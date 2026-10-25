<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Webhooks;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Credentials\CredentialVault;
use App\Credentials\EnvelopeCipher;
use App\Credentials\SealedSecret;
use App\Credentials\SecretString;
use App\Models\Repository;
use App\Models\WebhookIntegration;
use App\Source\Provider;
use App\Support\Uuid;

/**
 * The only place a webhook secret is created, opened or rotated.
 *
 * 🛑 One class for the same reason {@see CredentialVault}
 * is one class: this is where the audit event is written, and a second
 * unsealing path would be a secret read with no record of it. §8.19.3's
 * guarantee is about who may trigger a build, so "who looked at the key" is
 * part of the answer.
 *
 * 🛑 **The secret is 32 CSPRNG bytes** (§9.1.4's shape for an enumerable
 * security value) and is shown to the operator exactly once, at
 * provisioning, because it has to be pasted into the provider's own webhook
 * settings. After that it exists only as ciphertext: §8.19.1's API returns
 * the integration and never the secret, and
 * {@see WebhookIntegration::$hidden} keeps it out of a serialisation nobody
 * thought about.
 */
final readonly class IntegrationSecrets
{
    public function __construct(private EnvelopeCipher $cipher) {}

    public static function make(): self
    {
        return new self(EnvelopeCipher::fromConfig());
    }

    /**
     * Provision — or re-provision — the integration for a repository.
     *
     * 🛑 §8.3.6: "MUST re-provision idempotently without creating
     * duplicates." Re-provisioning an existing integration ROTATES its
     * secret in place rather than inserting a second row, so the
     * `UNIQUE (repository_id)` index is never the thing that reports the
     * mistake — and the repository keeps the same integration id, which is
     * in the webhook URL the provider already has.
     *
     * @param  SignatureScheme|null  $scheme  null takes the provider's default
     * @return array{0: WebhookIntegration, 1: SecretString} the secret, once
     */
    public function provision(
        Repository $repository,
        ?SignatureScheme $scheme = null,
        ?string $actorId = null,
    ): array {
        // Cast on the model, so this is already the enum.
        $provider = $repository->provider;

        $existing = WebhookIntegration::query()
            ->where('repository_id', $repository->id)
            ->first();

        $integration = $existing instanceof WebhookIntegration ? $existing : new WebhookIntegration;

        $integrationId = $existing instanceof WebhookIntegration
            ? $existing->id
            : Uuid::v7();

        $secret = bin2hex(random_bytes(32));

        $sealed = $this->cipher->seal(
            ['secret' => $secret],
            EnvelopeCipher::webhookAad($integrationId, $repository->organisation_id, $repository->id),
        );

        $integration->forceFill([
            'id' => $integrationId,
            'organisation_id' => $repository->organisation_id,
            'repository_id' => $repository->id,
            'provider' => $provider->value,
            'scheme' => ($scheme ?? ProviderProfile::for($provider)->defaultScheme)->value,
            'envelope_version' => $sealed->version,
            'kek_fingerprint' => $sealed->kekFingerprint,
            'wrapped_key' => $sealed->wrappedKey,
            'ciphertext' => $sealed->ciphertext,
            'state' => 'active',
            'rotated_at' => $existing instanceof WebhookIntegration ? now() : null,
        ])->save();

        Audit::record(
            action: $existing instanceof WebhookIntegration ? 'webhook.integration.rotated' : 'webhook.integration.provisioned',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $repository->organisation_id,
            actorId: $actorId,
            subjectType: 'webhook_integration',
            subjectId: $integrationId,
            payload: ['provider' => $provider->value, 'scheme' => $integration->scheme->value],
        );

        return [$integration, new SecretString($secret)];
    }

    /**
     * Unseal one integration's secret, for verification.
     *
     * 🛑 **No audit event here**, deliberately, and this is the one place
     * that differs from {@see CredentialVault}. Every
     * delivery opens this envelope, including every forged one, so auditing
     * the open would hand an unauthenticated caller an unbounded write to
     * the §8.22 hash chain — a chain whose per-organisation ordering makes
     * it exactly the wrong thing to let a stranger append to. The audit
     * event is written for the delivery's **outcome** instead, by
     * {@see WebhookIngestor}, which is one event per delivery rather than
     * one per attempt and still records every forgery.
     *
     * @throws \RuntimeException when no configured key opens the envelope
     */
    public function open(WebhookIntegration $integration): SecretString
    {
        $opened = $this->cipher->open(
            new SealedSecret(
                version: $integration->envelope_version,
                kekFingerprint: $integration->kek_fingerprint,
                wrappedKey: $integration->wrapped_key,
                ciphertext: $integration->ciphertext,
            ),
            EnvelopeCipher::webhookAad(
                $integration->id,
                $integration->organisation_id,
                $integration->repository_id,
            ),
        );

        $secret = $opened['secret'] ?? null;

        if (! $secret instanceof SecretString) {
            throw new \RuntimeException('a webhook envelope opened without a secret in it');
        }

        return $secret;
    }
}
