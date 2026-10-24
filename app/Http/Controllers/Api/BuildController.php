<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Builds\BuildAccess;
use App\Builds\BuildProgress;
use App\Http\Controllers\Controller;
use App\Models\Build;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * One build, with §8.5.23's queue position and estimated wait.
 *
 * > "The system MUST surface **queue position** and estimated wait in the
 * > UI, and MUST support cancelling a running build with effect within 5
 * > seconds."
 *
 * 🛑 **The position and the log cursor come from the same request.** A
 * client watching a build polls one endpoint for the log and would
 * otherwise poll a second for its state — and the two answers would come
 * from two snapshots, so a build could appear finished in one and still
 * queued in the other. The log endpoint carries `state` and `complete`
 * for exactly that reason; this endpoint is what a UI opens with.
 */
final class BuildController extends Controller
{
    public function __invoke(Request $request, string $build): JsonResponse
    {
        $model = BuildAccess::resolve($request, $build);

        if (! $model instanceof Build) {
            // §8.2.2: "404, never 403".
            abort(404);
        }

        return new JsonResponse([
            'build' => bin2hex($model->id),
            'state' => $model->state,
            'kind' => $model->kind,
            'failure_class' => $model->failure_class,
            'failure_identifier' => $model->failure_identifier,
            'exit_code' => $model->exit_code,
            'queued_at' => $model->queued_at?->toJSON(),
            'started_at' => $model->started_at?->toJSON(),
            'finished_at' => $model->finished_at?->toJSON(),
            'cancel_requested_at' => $model->cancel_requested_at?->toJSON(),
            'log' => [
                'lines' => (int) $model->log_lines,
                'bytes' => (int) $model->log_bytes,
                'capped' => (bool) $model->log_capped,
            ],
            ...BuildProgress::of($model)->jsonSerialize(),
        ], 200, ['Cache-Control' => 'no-store']);
    }
}
