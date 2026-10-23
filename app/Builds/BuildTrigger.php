<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Models\BuildRequest;
use App\Models\ProjectVersion;
use Illuminate\Database\UniqueConstraintViolationException;

/**
 * §8.5.3: eight trigger kinds, one row.
 *
 * > "Triggers MUST normalise into one request row from: provider webhook,
 * > generic webhook, manual, API, native per-version cron schedule,
 * > `ls-remote` poll, repository-change fan-out, and direct upload."
 *
 * 🛑 The normalisation is what makes §8.5.4's deduplication expressible at
 * all. Its first layer is "unique `(integration_id, delivery_id)`", and a
 * uniqueness constraint cannot span eight differently-shaped entry points —
 * so either they all become one row before anything else happens, or the
 * deduplication becomes eight slightly different checks, seven of which are
 * wrong by the time anyone notices.
 *
 * Phase 06 creates `manual` and `api` requests. The webhook kinds arrive with
 * §8.19.3's signature verification in Phase 11, and they arrive as *callers
 * of this class* rather than as a second way to start a build.
 */
final readonly class BuildTrigger
{
    /**
     * Record a trigger, deduplicating by delivery.
     *
     * 🛑 Returns the **existing** request when a provider redelivers. A
     * redelivery is not an error and must not be reported as one: providers
     * redeliver on their own schedule after a timeout, and a 500 in reply
     * teaches them to redeliver harder.
     *
     * @param  string|null  $deliveryId  the provider's own identifier, where there is one
     * @param  string|null  $actorId  raw 16 bytes
     */
    public function record(
        ProjectVersion $version,
        string $trigger,
        ?string $componentId = null,
        ?string $integrationId = null,
        ?string $deliveryId = null,
        ?string $actorId = null,
        bool $payloadTruncated = false,
    ): BuildRequest {
        $existing = $this->existingDelivery($integrationId, $deliveryId);

        if ($existing instanceof BuildRequest) {
            return $existing;
        }

        try {
            $request = new BuildRequest;
            $request->forceFill([
                'organisation_id' => $version->organisation_id,
                'project_version_id' => $version->id,
                'component_id' => $componentId,
                'trigger' => $trigger,
                'integration_id' => $integrationId,
                'delivery_id' => $deliveryId,
                'requested_by' => $actorId,
                'state' => 'queued',

                /*
                 * 🛑 §8.5.4: "Where a provider may truncate its changed-file
                 * arrays, the system MUST treat the payload as 'everything
                 * changed'." Carried on the row because the payload is not
                 * kept, and a changed-path skip rule must not be applied to a
                 * request whose flag is set.
                 */
                'payload_truncated' => $payloadTruncated,
            ])->save();
        } catch (UniqueConstraintViolationException) {
            // Two deliveries of the same event, concurrently. The index is
            // the arbiter; whoever lost reads the winner's row.
            $existing = $this->existingDelivery($integrationId, $deliveryId);

            if (! $existing instanceof BuildRequest) {
                throw new \RuntimeException('a build request collided with a row that does not exist');
            }

            return $existing;
        }

        Audit::record(
            action: 'build.requested',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $version->organisation_id,
            actorId: $actorId,
            subjectType: 'build_request',
            subjectId: $request->id,
            payload: ['trigger' => $trigger],
        );

        return $request;
    }

    private function existingDelivery(?string $integrationId, ?string $deliveryId): ?BuildRequest
    {
        if ($integrationId === null || $deliveryId === null) {
            // A manual trigger has no delivery id, and two manual triggers
            // are two requests. MySQL's treatment of NULL in a unique index
            // says the same thing, so the query and the constraint agree.
            return null;
        }

        return BuildRequest::query()
            ->where('integration_id', $integrationId)
            ->where('delivery_id', $deliveryId)
            ->first();
    }
}
