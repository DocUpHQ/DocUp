<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Artifacts\Exceptions\IngestRejected;
use App\Artifacts\IngestCaps;
use App\Artifacts\Publisher;
use App\Http\Controllers\Api\Concerns\ResolvesTokenActor;
use App\Models\ProjectVersion;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;

/**
 * The direct artifact upload API (§8.21.6).
 *
 * 🛑 §8.21.6: "A **direct artifact upload** API MUST accept a validated archive
 * … and reuse the collect, compose, store and publish stages unchanged. The
 * built-in runner MUST be implemented as the **first consumer** of this path,
 * not a privileged special case, so bring-your-own-CI is a permanent capability
 * rather than a deferred feature."
 *
 * That requirement is why this class does so little. It takes an upload, hands
 * it to {@see Publisher}, and renders the outcome. Every rule — §8.8.2's
 * validation, §8.8.10's quota, §8.8.4's compare-and-swap — lives behind that one
 * call, so the runner in Phase 06 arrives as another caller rather than as a
 * second implementation with its own near-miss of the same logic.
 */
final class VersionUploadController
{
    use ResolvesTokenActor;

    public function __construct(private readonly Publisher $publisher) {}

    /**
     * 🛑 Returns **202 with `published: false`** when the compare-and-swap lost,
     * not an error. §8.8.4's losing build is a success whose artifacts are
     * stored and selectable; a 409 or a 500 would have a CI pipeline retrying a
     * build that worked perfectly.
     */
    public function store(Request $request, string $project, string $version): JsonResponse
    {
        $caps = IngestCaps::fromConfig();

        /*
         * The framework's own size check, ahead of the ingestor's. It refuses an
         * over-large body before PHP has buffered all of it, which the §8.8.2
         * caps cannot do — they measure a file that has already arrived.
         */
        $request->validate([
            'archive' => ['required', 'file', 'max:'.(int) ceil($caps->totalBytes / 1024)],
        ]);

        $resolved = ProjectVersion::locate($project, $version);

        if (! $resolved instanceof ProjectVersion) {
            // §8.2.2: the same 404 for another tenant's project and for a
            // version that genuinely does not exist.
            return response()->json(['error' => 'not_found'], 404);
        }

        $upload = $request->file('archive');

        if (! $upload instanceof UploadedFile) {
            return response()->json(['error' => 'invalid_upload'], 422);
        }

        $path = $upload->getRealPath();

        if ($path === false) {
            return response()->json(['error' => 'invalid_upload'], 422);
        }

        try {
            $outcome = $this->publisher->publishUpload($resolved, $path, $this->actor($request));
        } catch (IngestRejected $rejection) {
            /*
             * 🛑 422 carrying the stable identifier, which is the whole point of
             * §8.19.15: the body says `contract.path_escapes_root`, not a
             * sentence. A CI script branches on the identifier; the message is
             * for the human reading the failure afterwards.
             */
            return response()->json([
                'error' => $rejection->rejection->value,
                'failure_class' => $rejection->rejection->failureClass(),
                'message' => $rejection->getMessage(),
            ], 422);
        }

        return response()->json($outcome->toArray(), $outcome->published ? 201 : 202);
    }
}
