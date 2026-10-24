<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Builds\BuildAccess;
use App\Builds\BuildConfig;
use App\Builds\Log\BuildLog;
use App\Builds\Log\BuildLogArchive;
use App\Builds\Log\LogPage;
use App\Http\Controllers\Controller;
use App\Models\Build;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * §8.5.22's one offset-addressed build-log contract.
 *
 * > "Build logs MUST be exposed through one offset-addressed contract
 * > (`GET /api/v3/builds/{id}/log?from=<seq>`) consumable by both
 * > transports. Polling MUST be the default and the only thing in the
 * > core compose file; WebSocket streaming MUST be an optional profile.
 * > Log access MUST be authorised by the same policy as the project, and
 * > build-log visibility for anonymous readers of public projects MUST be
 * > a per-project setting defaulting to **off**."
 *
 * 🛑 **One contract, two transports, and the second one is not here.**
 * The WebSocket profile of §19/22 reads the same pages from the same
 * method; what it adds is a push instead of a poll. Writing it as a
 * second endpoint with its own serialisation is how the two come to
 * disagree about a cursor, so the paging, the gap report and the
 * termination condition all live in {@see BuildLog::pageFrom()} and this
 * controller only chooses a content type.
 *
 * 🛑 **`complete` is what stops the poll**, and it is derived from the
 * build's state rather than from an empty page. An empty page means
 * "nothing new yet" during a nine-minute build and "that is all there
 * is" after it ends, and a client that could not tell them apart would
 * either stop early or poll a finished build for ever.
 */
final class BuildLogController extends Controller
{
    public function __construct(private readonly BuildLogArchive $archive) {}

    public function __invoke(Request $request, string $build): Response
    {
        $model = BuildAccess::resolve($request, $build);

        if (! $model instanceof Build) {
            // §8.2.2's "404, never 403": a caller who may not read this
            // build must not learn that it exists.
            abort(404);
        }

        $from = max(1, (int) $request->query('from', '1'));
        $limit = BuildConfig::positiveInt('log_page_lines', 2000);
        $page = $this->page($model, $from, $limit);
        $complete = $model->isTerminal();

        /*
         * NDJSON when asked for, JSON otherwise. §8.5.21 names NDJSON as
         * the streaming form and §8.5.22 names one contract — so the two
         * are the same endpoint under different `Accept` headers rather
         * than two paths that drift.
         */
        if (str_contains((string) $request->header('Accept'), 'application/x-ndjson')) {
            return response($page->toNdjson(), 200, [
                'Content-Type' => 'application/x-ndjson',
                'Cache-Control' => 'no-store',
                'X-DocUp-Log-Next' => (string) $page->next,
                'X-DocUp-Log-Complete' => $complete ? '1' : '0',
            ]);
        }

        return new JsonResponse([
            'build' => bin2hex($model->id),
            'state' => $model->state,
            'complete' => $complete,
            'capped' => (bool) $model->log_capped,
            ...$page->jsonSerialize(),
        ], 200, ['Cache-Control' => 'no-store']);
    }

    /**
     * The live file while a build runs; the archive once it has ended.
     *
     * 🛑 Live first, even for a terminal build. A build that finished a
     * moment ago may not have been archived yet — `sealLog()` runs in the
     * pipeline's `finally` — and a reader who asked at that instant
     * should get the log that exists rather than an empty page followed
     * by a full one.
     */
    private function page(Build $model, int $from, int $limit): LogPage
    {
        $live = BuildLog::open(bin2hex($model->id));

        if ($live->exists()) {
            return $live->read($from, $limit);
        }

        return $this->archive->read($model, $from, $limit);
    }
}
