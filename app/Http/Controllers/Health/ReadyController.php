<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Health;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

/**
 * Readiness (§8.1.10): should traffic come here?
 *
 * 🛑 A different question from liveness, and conflating the two is how an
 * orchestrator comes to restart a healthy container during a database
 * incident. This one checks the dependencies a request needs and answers
 * 503 when they are missing; {@see LiveController} deliberately checks
 * nothing.
 *
 * It reveals no hostname, no version and no credential — just whether each
 * dependency answered.
 */
final class ReadyController extends Controller
{
    public function __invoke(): JsonResponse
    {
        $checks = [
            'database' => $this->probe(static fn () => DB::connection()->getPdo()),
            'cache' => $this->probe(static fn () => Cache::store()->get('docup:health')),
        ];

        $ready = ! in_array(false, $checks, true);

        return response()
            ->json(['status' => $ready ? 'ready' : 'not_ready', 'checks' => $checks])
            ->setStatusCode($ready ? 200 : 503)
            ->header('Cache-Control', 'no-store');
    }

    private function probe(\Closure $check): bool
    {
        try {
            $check();

            return true;
        } catch (\Throwable) {
            return false;
        }
    }
}
