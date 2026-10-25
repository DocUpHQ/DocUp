<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Webhooks;

use App\Models\IncomingWebhookDelivery;
use App\Models\WebhookIntegration;
use App\Support\Uuid;
use Illuminate\Database\UniqueConstraintViolationException;

/**
 * §8.19.3's replay protection where the provider supplies no timestamp.
 *
 * > "🛑 Where no timestamp exists (Bitbucket), replay protection MUST fall
 * > back to delivery-id uniqueness, and that weaker guarantee MUST be
 * > documented."
 *
 * 🛑 **How much weaker, stated, because the requirement asks for it to be
 * documented and a comment nobody can act on is not documentation.** A
 * timestamp window needs no state and bounds replay at five minutes
 * absolutely. Delivery-id uniqueness bounds it at this table's retention
 * (§20: 30 days default, 7-day floor, 90-day ceiling, `config/webhooks.php`),
 * and only for deliveries this installation actually received: a delivery
 * captured and replayed after its row is purged verifies again and is
 * indistinguishable from a redelivery.
 *
 * What that is worth in practice, and why it is accepted rather than worked
 * around: the replayed payload names a commit, §8.5.1 re-pins every ref with
 * `ls-remote` before a build runs, and §8.5.2 resolves a trigger whose plan
 * digest matches the published build to `unchanged` with no container
 * started. So the realistic outcome of a successful replay is one row in
 * `build_requests` and no build. It is still a trigger the attacker caused,
 * which is why it is refused with a 401 rather than tolerated.
 *
 * 🛑 This also applies to **three of the four schemes**, not only to
 * Bitbucket: GitHub, Gitea and Forgejo send no timestamp either. Reading the
 * requirement as "Bitbucket is the exception" leaves GitHub unprotected,
 * which is the opposite of the intended reading.
 */
final readonly class DeliveryLedger
{
    /**
     * Record a delivery, or report that it has been seen before.
     *
     * 🛑 The uniqueness constraint is the arbiter, not a prior `exists()`
     * query. Two copies of one delivery arriving concurrently — which is
     * exactly what a replay attempt looks like, and also what a provider's
     * retry looks like when the first attempt timed out — would both pass a
     * check-then-insert, and the second would be admitted.
     *
     * @return bool true when this delivery is new
     */
    public function record(WebhookIntegration $integration, string $deliveryId, ?string $event): bool
    {
        $delivery = new IncomingWebhookDelivery;

        try {
            $delivery->forceFill([
                'id' => Uuid::v7(),
                'organisation_id' => $integration->organisation_id,
                'integration_id' => $integration->id,
                'delivery_id' => $deliveryId,
                'event' => $event,
                'received_at' => now(),
            ])->save();
        } catch (UniqueConstraintViolationException) {
            return false;
        }

        return true;
    }
}
