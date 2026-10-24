<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Builds\BuildAccess;
use App\Http\Controllers\Controller;
use App\Http\Middleware\AuthenticateApiToken;
use App\Models\ApiToken;
use App\Models\Build;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

/**
 * §8.5.23's cancellation: "with effect within 5 seconds".
 *
 * 🛑 **This endpoint records a request; it does not stop anything.** The
 * process that can stop a container is the runner, which has no database
 * and no listening port (§8.5.13, §11.2) — so the request lands on the
 * build row, the worker relays it into the spool on its next 200 ms
 * tick, and the runner's output loop sees the marker within half a
 * second and kills the container. Five seconds is the budget for that
 * whole chain, and every hop in it is bounded by an interval rather than
 * by a timeout somebody tuned.
 *
 * 🛑 **Idempotent, and it says so.** A UI whose cancel button was
 * double-clicked, or a CI job retrying on a timeout, must not produce two
 * audit events or two markers. The first request wins and every later one
 * returns the same answer.
 */
final class BuildCancelController extends Controller
{
    public function __invoke(Request $request, string $build): JsonResponse
    {
        $model = BuildAccess::resolve($request, $build);

        /*
         * 🛑 Anonymous callers never reach this. `BuildAccess` will hand
         * back a build for an anonymous reader of a public project with
         * logs enabled — which is correct for READING — so cancellation
         * checks for the credential itself. Reading a log and stopping
         * somebody's build are not the same permission, and the one place
         * that could confuse them is here.
         */
        $token = $request->attributes->get(AuthenticateApiToken::ATTRIBUTE);

        if (! $model instanceof Build || ! $token instanceof ApiToken) {
            // §8.2.2: "404, never 403".
            abort(404);
        }

        if ($model->isTerminal()) {
            return new JsonResponse([
                'build' => bin2hex($model->id),
                'state' => $model->state,
                'cancelled' => false,
                'detail' => 'this build has already finished',
            ], 409, ['Cache-Control' => 'no-store']);
        }

        if ($model->cancel_requested_at === null) {
            DB::transaction(function () use ($model, $token): void {
                $model->forceFill([
                    'cancel_requested_at' => now(),
                    'cancel_requested_by' => $token->user_id,
                ])->save();

                Audit::record(
                    action: 'build.cancel.requested',
                    actorType: ActorType::ApiToken,
                    organisationId: $model->organisation_id,
                    actorId: $token->user_id,
                    subjectType: 'build',
                    subjectId: $model->id,
                );
            });

            $model->refresh();
        }

        return new JsonResponse([
            'build' => bin2hex($model->id),
            'state' => $model->state,
            'cancelled' => true,
            'cancel_requested_at' => $model->cancel_requested_at?->toJSON(),
        ], 202, ['Cache-Control' => 'no-store']);
    }
}
