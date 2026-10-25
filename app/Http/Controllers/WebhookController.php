<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Builds\RepositoryFanout;
use App\Models\Repository;
use App\Models\WebhookIntegration;
use App\Webhooks\DeliveryHeaders;
use App\Webhooks\WebhookIngestor;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * The incoming webhook endpoint (§8.19.3).
 *
 * 🛑 **There is exactly one**, it takes an integration id, and it verifies a
 * signature before it does anything else. §8.19.3: "An **unsigned** generic
 * webhook endpoint MUST NOT exist — Read the Docs ships one and it is a
 * build-trigger oracle." `tests/Feature/Webhooks/WebhookRouteTest.php`
 * asserts the absence by walking the route table, because an absence is the
 * one thing a feature test of the present routes cannot prove.
 *
 * 🛑 The controller is deliberately almost empty. Every decision lives in
 * {@see WebhookIngestor}, which is the single call site §4.3/7's discipline
 * asks for on a path like this one: a second controller that did its own
 * verification would be a second place for an authentication bypass.
 */
final class WebhookController extends Controller
{
    public function __invoke(
        Request $request,
        string $integration,
        WebhookIngestor $ingestor,
        RepositoryFanout $fanout,
    ): JsonResponse {
        /*
         * 🛑 `getContent()`, never `$request->all()` or `->json()`.
         * §8.19.3 requires the HMAC over the **raw** body, and a decoded
         * then re-encoded body is different bytes — see
         * {@see \App\Webhooks\RawBodyVerifier} for what that costs.
         */
        $delivery = $ingestor->ingest(
            integrationId: $integration,
            rawBody: $request->getContent(),
            headers: new DeliveryHeaders($request->headers->all()),
        );

        if (! $delivery->wasAccepted()) {
            /*
             * One shape for every refusal, carrying the §8.1.11 identifier
             * and nothing else. No hint about which integration exists, no
             * echo of the signature, no timing difference worth measuring —
             * the work before this point is the same for a forgery and for
             * a genuine delivery, because the lookup and the unseal happen
             * before the comparison.
             */
            return response()->json(
                ['error' => $delivery->rejection?->value],
                $delivery->status(),
            );
        }

        $integrationModel = $delivery->integration;
        $repository = $integrationModel?->repository;

        if (! $integrationModel instanceof WebhookIntegration || ! $repository instanceof Repository) {
            // Verified against an integration whose repository has since
            // been removed. Accepted — the sender did nothing wrong — and
            // acted on by nobody.
            return response()->json(['accepted' => 0], 202);
        }

        $enqueued = 0;
        $skipped = 0;

        foreach ($delivery->events as $event) {
            $outcome = $fanout->dispatch(
                repository: $repository,
                event: $event,
                triggerKind: 'webhook',
                integrationId: $integrationModel->id,
            );

            $enqueued += count($outcome->enqueued);
            $skipped += count($outcome->skipped);
        }

        /*
         * 202 rather than 200: the builds have not happened, they have been
         * accepted. Providers display the status beside the delivery, and
         * an operator reading "200" beside a push that produced nothing has
         * been told the wrong thing.
         */
        return response()->json(['accepted' => $enqueued, 'skipped' => $skipped], 202);
    }
}
