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
 * Clear the pin a rollback left behind (§8.8.5).
 *
 * 🛑 Deliberately a separate, deliberate act. §8.8.5 blocks automatic
 * republication "until a human unpins", so an automatic unpin on the next build
 * would be the pin not existing.
 *
 * There is no endpoint to *set* a pin, and that is not an omission: a pin means
 * "this version was rolled back and must not republish itself", so one set
 * without a rollback would record something untrue. Pausing a version that has
 * not been rolled back is what `publish_mode: manual` is for (§8.8.7).
 */
final class VersionPinController
{
    use ResolvesTokenActor;

    public function __construct(private readonly Publisher $publisher) {}

    public function destroy(Request $request, string $project, string $version): JsonResponse
    {
        $resolved = ProjectVersion::locate($project, $version);

        if (! $resolved instanceof ProjectVersion) {
            return response()->json(['error' => 'not_found'], 404);
        }

        $this->publisher->unpin($resolved, $this->actor($request));

        return response()->json(['pinned' => false]);
    }
}
