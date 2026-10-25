<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Webhooks;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\OrganisationContext;
use App\Models\Repository;
use App\Models\WebhookIntegration;
use App\Source\Provider;
use App\Support\Uuid;

/**
 * The one way a webhook delivery becomes something DocUp acts on
 * (§8.19.3).
 *
 * 🛑 **One class, one call site**, in the spirit of §4.3/7's single
 * `ArtifactIngestor`: this is the only unauthenticated write path in the
 * application, and an application with two of them has two places for an
 * authentication bypass to live. An architecture test asserts that nothing
 * outside this namespace calls {@see SignatureScheme::verify()}.
 *
 * The order below is the security property, and it is deliberate:
 *
 *   1. **The body cap, before anything reads the body.** Same discipline as
 *      §8.4.9's YAML gate: a limit applied after parsing is not a limit.
 *   2. **Resolve the integration**, across all organisations, because the
 *      tenant is not known until the integration is. Nothing is trusted
 *      from the request to decide this except the id in the URL — which
 *      proves nothing on its own, and is why step 4 exists.
 *   3. **Unseal and verify**, constant-time, over the raw bytes.
 *   4. **Replay**, by the provider's timestamp where it has one and by
 *      delivery-id uniqueness where it does not.
 *   5. **Parse**, treating every field as untrusted.
 *   6. **Cross-check the repository identifier**, so a verified delivery for
 *      repository A cannot act on repository B.
 *
 * 🛑 An unknown integration and an invalid signature are **the same answer**
 * to the caller: 401, no body, no detail. The id is in the URL where anyone
 * can try one, and a 404 for "no such integration" beside a 401 for "wrong
 * secret" enumerates which ids exist.
 */
final readonly class WebhookIngestor
{
    public function __construct(
        private IntegrationSecrets $secrets,
        private DeliveryLedger $ledger,
        private RawBodyVerifier $verifier = new RawBodyVerifier,
    ) {}

    public static function make(): self
    {
        return new self(IntegrationSecrets::make(), new DeliveryLedger);
    }

    /**
     * Verify one delivery and read its pushes.
     *
     * @param  string  $integrationId  the id from the URL, as text
     * @param  string  $rawBody  🛑 the bytes as received; never re-encoded
     * @param  int|null  $now  unix seconds, injected so the window is testable
     */
    public function ingest(
        string $integrationId,
        string $rawBody,
        DeliveryHeaders $headers,
        ?int $now = null,
    ): VerifiedDelivery {
        $now ??= time();

        /*
         * 🛑 Step 1. Before `json_decode`, before the integration lookup,
         * before anything touches the database. §8.4.9 learned this for
         * YAML and the reasoning transfers unchanged: a 200 MB body that is
         * rejected after parsing has already cost the memory.
         *
         * 401 rather than 413, because the body is what the HMAC covers: a
         * body we refuse to read is a body we cannot verify, and a distinct
         * status would tell an unauthenticated caller that their guess at an
         * integration id was right.
         */
        $cap = config('webhooks.max_body_bytes');

        if (is_int($cap) && strlen($rawBody) > $cap) {
            return VerifiedDelivery::refused(WebhookRejection::BodyTooLarge);
        }

        $integration = $this->resolve($integrationId);

        if (! $integration instanceof WebhookIntegration) {
            return VerifiedDelivery::refused(WebhookRejection::UnknownIntegration);
        }

        if (! $integration->isActive()) {
            return VerifiedDelivery::refused(WebhookRejection::IntegrationDisabled, $integration);
        }

        $profile = $integration->profile();
        $scheme = $integration->scheme;
        $deliveryId = $profile->deliveryId($headers);
        $event = $profile->event($headers);

        try {
            $secret = $this->secrets->open($integration);
        } catch (\RuntimeException) {
            /*
             * No configured key opens the envelope — a KEK rotated without
             * the previous key kept, or a restored backup. Reported as a
             * signature failure because that is what it is from the
             * caller's side, and audited so an operator sees it: an
             * integration that can never verify again is a repository that
             * has silently stopped building.
             */
            $this->audit($integration, WebhookRejection::SignatureInvalid, $deliveryId, $event, keyFailure: true);

            return VerifiedDelivery::refused(WebhookRejection::SignatureInvalid, $integration, $deliveryId, $event);
        }

        $rejection = $scheme->verify($headers, $rawBody, $secret->reveal(), $profile, $this->verifier, $now);

        if ($rejection instanceof WebhookRejection) {
            $this->audit($integration, $rejection, $deliveryId, $event);

            return VerifiedDelivery::refused($rejection, $integration, $deliveryId, $event);
        }

        /*
         * 🛑 Step 4, and only now: the ledger is written for deliveries
         * whose signature VERIFIED. Recording unverified ones would let an
         * unauthenticated caller fill the table — and then replay a genuine
         * delivery, because its id would already be "seen".
         */
        if ($scheme->needsDeliveryIdReplayProtection()) {
            if ($deliveryId === null) {
                $this->audit($integration, WebhookRejection::DeliveryIdMissing, null, $event);

                return VerifiedDelivery::refused(WebhookRejection::DeliveryIdMissing, $integration, null, $event);
            }

            if (! $this->ledger->record($integration, $deliveryId, $event)) {
                $this->audit($integration, WebhookRejection::DeliveryReplayed, $deliveryId, $event);

                return VerifiedDelivery::refused(WebhookRejection::DeliveryReplayed, $integration, $deliveryId, $event);
            }
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($rawBody, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return VerifiedDelivery::refused(WebhookRejection::BodyMalformed, $integration, $deliveryId, $event);
        }

        if (! is_array($decoded)) {
            return VerifiedDelivery::refused(WebhookRejection::BodyMalformed, $integration, $deliveryId, $event);
        }

        $events = $profile->parser->parse($decoded, $event, $headers);

        if ($events === []) {
            return VerifiedDelivery::refused(WebhookRejection::UnsupportedEvent, $integration, $deliveryId, $event);
        }

        if (! $this->identifiesTheSameRepository($integration, $events[0])) {
            $this->audit($integration, WebhookRejection::RepositoryMismatch, $deliveryId, $event);

            return VerifiedDelivery::refused(WebhookRejection::RepositoryMismatch, $integration, $deliveryId, $event);
        }

        $integration->forceFill(['last_delivery_at' => now()])->save();

        return VerifiedDelivery::accepted($integration, $events, $deliveryId, $event);
    }

    /**
     * Find the integration named in the URL, across every organisation.
     *
     * 🛑 Unscoped for the same reason `App\Auth\ApiTokens` is: the tenant is
     * a property of the credential, and a scoped lookup would need a tenant
     * to find the thing that determines the tenant. The context is set to
     * the integration's organisation immediately after, so everything below
     * this line is scoped normally.
     */
    private function resolve(string $integrationId): ?WebhookIntegration
    {
        $bytes = Uuid::tryToBytes($integrationId);

        if ($bytes === null) {
            return null;
        }

        $context = app(OrganisationContext::class);

        /** @var WebhookIntegration|null $integration */
        $integration = $context->acrossAllOrganisations(
            static fn (): ?WebhookIntegration => WebhookIntegration::query()->find($bytes),
        );

        if ($integration instanceof WebhookIntegration) {
            $context->for($integration->organisation_id);
        }

        return $integration;
    }

    /**
     * 🛑 §10.2's stable identifier, cross-checked.
     *
     * A verified delivery proves the sender holds this integration's secret.
     * It does not prove the payload describes this integration's repository,
     * and a provider misconfigured to point repository A's webhook at
     * repository B's integration URL would otherwise let whoever controls A
     * trigger builds of B.
     *
     * Absent on either side is not a mismatch: §8.3.8 allows a repository
     * with no provider-stable identifier, and the generic provider sends
     * none by design. Those fall back to the binding the URL and the secret
     * already establish, which is what §8.3.8's "degrade to normalised-URL
     * matching" means here.
     */
    private function identifiesTheSameRepository(WebhookIntegration $integration, PushEvent $event): bool
    {
        if ($event->repositoryIdentifier === null) {
            return true;
        }

        $repository = $integration->repository;

        if (! $repository instanceof Repository) {
            return false;
        }

        $stored = $repository->provider_repo_id;

        if ($stored === null || $stored === '') {
            return true;
        }

        $provider = $integration->provider;

        /*
         * Canonicalised on both sides: `{A1B2…}` and `a1b2…` are the same
         * Bitbucket repository, and `042` and `42` the same GitHub one.
         *
         * An ordinary `===`, not `hash_equals`: a repository identifier is
         * not a secret — the sender wrote it and the provider publishes it
         * — so there is nothing for a timing side channel to leak. Using
         * the constant-time comparison here anyway would blur the one
         * place it genuinely matters, which is why the architecture test
         * allows it in `RawBodyVerifier` and nowhere else in this
         * namespace.
         */
        $presented = $provider->canonicaliseIdentifier($event->repositoryIdentifier);

        return $presented !== null && $presented === $stored;
    }

    /**
     * One audit event per refused delivery.
     *
     * 🛑 §8.19.3's exit criterion: "A forged signature, and a valid
     * signature replayed outside the window, each return 401 and **are
     * audited**." Written here rather than in the controller so that a
     * second caller of the ingestor cannot forget it.
     *
     * Only security-significant rejections are recorded — see
     * {@see WebhookRejection::isSecuritySignificant()}. A `ping` every
     * minute from forty repositories would bury the one forgery.
     */
    private function audit(
        WebhookIntegration $integration,
        WebhookRejection $rejection,
        ?string $deliveryId,
        ?string $event,
        bool $keyFailure = false,
    ): void {
        if (! $rejection->isSecuritySignificant()) {
            return;
        }

        Audit::record(
            action: 'webhook.delivery.refused',
            actorType: ActorType::System,
            organisationId: $integration->organisation_id,
            subjectType: 'webhook_integration',
            subjectId: $integration->id,
            reasonCode: $rejection->value,
            payload: [
                /*
                 * The delivery id and the event name, both provider-supplied
                 * and both untrusted. They are stored, never matched
                 * against, and escaped on render — §8.3.7's treatment of
                 * every provider response, applied to the one that arrives
                 * by webhook.
                 */
                'delivery_id' => $deliveryId,
                'event' => $event,
                'scheme' => $integration->scheme->value,
                'key_failure' => $keyFailure,
            ],
        );
    }
}
