<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Jobs;

use App\Auth\OrganisationContext;
use App\Builds\BuildPipeline;
use App\Models\BuildRequest;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;

/**
 * One recorded build request, handed to the pipeline by a worker.
 *
 * Phase 06 built the pipeline and Phase 11 is the first thing that calls it
 * without a human present, so this is the first queued job in the
 * application. It is deliberately thin: the request row already exists and
 * already carries everything the pipeline needs, so the job's whole payload
 * is an id.
 *
 * 🛑 **The id, not the model.** A serialised model would carry a snapshot of
 * the row as it was when the webhook arrived, and the gap between enqueue
 * and execution is exactly where §8.5.4's fourth layer operates: a newer
 * request may have superseded this one, and the pipeline decides that by
 * reading the database rather than by trusting a payload written before the
 * newer request existed. Laravel's `SerializesModels` would re-fetch, but it
 * would re-fetch THROUGH the tenancy scope with no tenant set — which
 * throws, in a worker, where nobody is watching.
 *
 * 🛑 **`tries = 1`.** §8.5.16: "Repository-content and configuration
 * failures MUST NOT be retried automatically. Only infrastructure-classified
 * stages MUST retry, with bounded backoff." The pipeline classifies its own
 * failures and retries the stages that deserve it; a queue-level retry would
 * re-run the whole build for a typo in `conf.py`, twenty-five more times,
 * and §8.5.17's governor counts user-caused failures.
 */
final class RunBuild implements ShouldQueue
{
    use Queueable;

    /** §8.5.16: the pipeline owns retry, not the queue. */
    public int $tries = 1;

    /** @param string $requestId raw 16 bytes */
    public function __construct(private readonly string $requestId) {}

    public function handle(BuildPipeline $pipeline, OrganisationContext $context): void
    {
        /*
         * The worker has no tenant, so the request is found across all
         * organisations and the context is then set from it — the same
         * shape `App\Auth\ApiTokens` and `App\Webhooks\WebhookIngestor`
         * use, and for the same reason: the tenant is a property of the
         * thing being looked up.
         */
        /** @var BuildRequest|null $request */
        $request = $context->acrossAllOrganisations(
            fn (): ?BuildRequest => BuildRequest::query()->find($this->requestId),
        );

        if (! $request instanceof BuildRequest) {
            // The request was deleted between enqueue and execution — a
            // project removed, an organisation closed. Nothing to do, and
            // nothing worth failing a job over.
            return;
        }

        if ($request->isTerminal()) {
            // Settled while it waited: superseded by a newer push, or
            // skipped by a rule that fired after this job was queued.
            return;
        }

        $context->for($request->organisation_id);

        $pipeline->run($request);
    }

    /** For a test asserting WHICH request was enqueued. */
    public function requestId(): string
    {
        return $this->requestId;
    }
}
