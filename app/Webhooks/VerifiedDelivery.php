<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Webhooks;

use App\Models\WebhookIntegration;

/**
 * What {@see WebhookIngestor} produces: either a rejection or an
 * authenticated delivery with its pushes.
 *
 * 🛑 One type with a nullable rejection rather than an exception, because
 * every outcome here is ordinary. A `ping` is not exceptional, a replay is
 * not exceptional, and a forged signature is the thing the endpoint exists
 * to handle — throwing for any of them would put the normal flow of an
 * unauthenticated endpoint through a catch block, which is how a `finally`
 * ends up auditing the wrong thing.
 */
final readonly class VerifiedDelivery
{
    /** @param list<PushEvent> $events */
    private function __construct(
        public ?WebhookRejection $rejection,
        public ?WebhookIntegration $integration,
        public array $events,
        public ?string $deliveryId,
        public ?string $event,
    ) {}

    public static function refused(
        WebhookRejection $rejection,
        ?WebhookIntegration $integration = null,
        ?string $deliveryId = null,
        ?string $event = null,
    ): self {
        return new self($rejection, $integration, [], $deliveryId, $event);
    }

    /** @param list<PushEvent> $events */
    public static function accepted(
        WebhookIntegration $integration,
        array $events,
        ?string $deliveryId,
        ?string $event,
    ): self {
        return new self(null, $integration, $events, $deliveryId, $event);
    }

    public function wasAccepted(): bool
    {
        return $this->rejection === null;
    }

    /** The HTTP status to answer with; see {@see WebhookRejection::status()}. */
    public function status(): int
    {
        return $this->rejection?->status() ?? 202;
    }
}
