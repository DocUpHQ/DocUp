<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Models\BuildRequest;
use App\Models\Project;
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
    public function __construct(
        /**
         * §8.5.17's governor, asked only about webhook-shaped triggers.
         *
         * Injected rather than resolved inside the check, so a test can
         * exercise the refusal without arranging twenty-six failed builds
         * first — and so the one place that decides "is this a webhook"
         * is visible beside the one place that decides "is it allowed".
         */
        private BuildGovernor $governor = new BuildGovernor,
    ) {}

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
    /**
     * Record the request row, however it will be settled.
     *
     * 🛑 One construction site, shared by the normal path and §8.5.17's
     * refusal. A refused request built from its own literal array would
     * drift from this one — and the column that drifted would be
     * `payload_truncated`, which §8.5.4 makes load-bearing.
     */
    private function open(
        ProjectVersion $version,
        string $trigger,
        ?string $componentId,
        ?string $integrationId,
        ?string $deliveryId,
        ?string $actorId,
        bool $payloadTruncated,
    ): BuildRequest {
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

        return $request;
    }

    /**
     * The trigger kinds §8.5.17's governor applies to.
     *
     * 🛑 A list of what IS governed, not of what is exempt. The exempt
     * set would have to be extended by whoever adds the next trigger
     * kind, and the cost of forgetting is a tenant locked out of the
     * manual build that was supposed to be their way back.
     */
    private function isWebhookTrigger(string $trigger): bool
    {
        return in_array($trigger, ['webhook', 'generic_webhook', 'repository_fanout'], true);
    }

    private function governorPermits(ProjectVersion $version): bool
    {
        $project = $version->project;

        return ! $project instanceof Project || $this->governor->permitsWebhookTrigger($project);
    }

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

        /*
         * 🛑 §8.5.17's governor, consulted HERE and only for the trigger
         * kinds it governs: "disables **webhook** triggering (never
         * manual)". A manual or API trigger never reaches this branch,
         * which is the requirement expressed as the absence of a check
         * rather than as a comment — a tenant who cannot press Build
         * cannot clear the condition that disabled them.
         *
         * The request is still recorded, settled as refused with a stable
         * identifier. Dropping it would leave the provider's delivery with
         * no trace, and the first question anybody asks about a project
         * that stopped building is "did the webhook arrive?".
         */
        if ($this->isWebhookTrigger($trigger) && ! $this->governorPermits($version)) {
            $request = $this->open($version, $trigger, $componentId, $integrationId, $deliveryId, $actorId, $payloadTruncated);
            $request->settle('rejected', 'rejected.webhook_triggering_disabled');

            return $request;
        }

        try {
            $request = $this->open($version, $trigger, $componentId, $integrationId, $deliveryId, $actorId, $payloadTruncated);
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
