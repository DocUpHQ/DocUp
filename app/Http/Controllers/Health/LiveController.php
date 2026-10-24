<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Health;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;

/**
 * Liveness (§8.1.10). See the sibling controllers in this namespace.
 *
 * > "The system MUST expose `/_/health` (liveness), `/_/health/ready`
 * > (readiness) and `/_/health/self-test` (trust-zone and private-cache
 * > assertions), and a Prometheus `/metrics` endpoint (§15.1)."
 *
 * 🛑 **Found missing in Phase 07, and the way it was missing is the point.**
 * `bootstrap/app.php` passes `health: '/up'` to `withRouting()` — and that
 * parameter is **silently ignored when `using:` is supplied**, which it is,
 * for the route-ordering reason recorded there. So `/up` 404'd, the
 * compose healthcheck curled it on a ten-second interval, and
 * `docup-app-1` had been reporting **unhealthy since Phase 01**. Phase 01's
 * own build log records catching exactly this on the worker container and
 * drawing the right conclusion — "a configuration comment cannot fail a
 * build; assert the outcome" — while the same defect sat on the
 * application container the whole time.
 *
 * 🛑 **Three endpoints, three different questions**, and conflating them is
 * how an orchestrator comes to restart a healthy container:
 *
 *  - *liveness* asks "is this process running": it must not touch the
 *    database, because a database outage that restarted every application
 *    container would turn a recoverable incident into an outage of its own;
 *  - *readiness* asks "should traffic come here": it checks the
 *    dependencies a request needs;
 *  - *self-test* asks "are the invariants still true": §8.5.12's trust-zone
 *    verdict today, and §8.12.22's private-asset containment when Phase 21
 *    builds it.
 *
 * None of them reveals a hostname, a credential or a version. An endpoint
 * reachable without authentication answers yes or no and says nothing a
 * reader could not already infer by making a request.
 *
 * 🛑 **Three single-action controllers rather than one with three
 * methods.** The `laravel` architecture preset (§9.4) holds controllers to
 * the resource verbs, and these are not resources. Splitting them conforms
 * to the rule instead of exempting a file from it — and it happens to be
 * the right shape anyway, since the three share no state and have
 * different failure semantics.
 */
final class LiveController extends Controller
{
    /**
     * 🛑 Dependency-free, deliberately.
     *
     * Liveness asks "is this process running". A database outage that
     * restarted every application container would turn a recoverable
     * incident into an outage of its own, so this endpoint touches
     * nothing.
     */
    public function __invoke(): JsonResponse
    {
        return response()->json(['status' => 'ok'])->header('Cache-Control', 'no-store');
    }
}
