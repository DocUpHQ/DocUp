<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Artifacts\Publisher;
use App\Http\Controllers\Api\Concerns\ResolvesTokenActor;
use App\Models\ProjectVersion;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Roll a version back one manifest revision, pinning it (§8.8.5).
 *
 * 🛑 §8.8.5: "Rollback MUST be the same pointer flip backwards, plus a pin that
 * blocks automatic republication until a human unpins." Both halves happen in
 * {@see Publisher::rollback()} inside one transaction — a flip without the pin
 * would be undone by the next successful build, which is the worst available
 * response to somebody deciding a release was bad.
 */
final class VersionRollbackController
{
    use ResolvesTokenActor;

    public function __construct(private readonly Publisher $publisher) {}

    public function __invoke(Request $request, string $project, string $version): JsonResponse
    {
        $resolved = ProjectVersion::locate($project, $version);

        if (! $resolved instanceof ProjectVersion) {
            return response()->json(['error' => 'not_found'], 404);
        }

        $reason = $request->string('reason')->trim()->value();

        try {
            $outcome = $this->publisher->rollback(
                version: $resolved,
                reason: $reason === '' ? 'Rolled back through the API.' : $reason,
                actorId: $this->actor($request),
            );
        } catch (\RuntimeException $e) {
            /*
             * Nothing to roll back to is the caller's situation, not a fault:
             * 409 says "the resource is not in a state that allows this". A 500
             * would page somebody because a CI script asked a reasonable
             * question and got a reasonable no.
             */
            return response()->json(['error' => 'conflict', 'message' => $e->getMessage()], 409);
        }

        return response()->json($outcome->toArray());
    }
}
