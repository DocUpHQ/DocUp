<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Health;

use App\Builds\Runner\Spool;
use App\Builds\Sandbox\SandboxPolicy;
use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;

/**
 * §8.1.10's "trust-zone … assertions", from §8.5.12's own verdict.
 *
 * 🛑 **It reports the verdict rather than running the test.** The test
 * launches a container and only the runner may do that (§8.5.13); a request
 * handler that could would be a request handler holding the runtime socket,
 * which is the one thing §8.5.13 forbids by name. The runner writes its
 * verdict to the spool at boot and this reads it.
 *
 * 🛑 A **missing** verdict is reported as a failure, not as unknown. No
 * verdict means no runner has started since this spool existed, so nothing
 * has checked the sandbox — which is the same operational fact as a
 * failure, and this endpoint exists to surface facts.
 *
 * §8.12.22's private-asset containment assertion joins this response when
 * Phase 22 builds the authorisation kernel it probes.
 */
final class SelfTestController extends Controller
{
    public function __invoke(Spool $spool, SandboxPolicy $policy): JsonResponse
    {
        $verdict = $spool->readSelfTest();

        $body = [
            'builds_enabled' => $policy->buildsEnabled,
            'isolation' => $policy->isolation,
            'egress' => $policy->egress->value,
            'sandbox_isolation' => match (true) {
                ! $policy->buildsEnabled => 'not_applicable',
                $verdict === null => 'never_run',
                $verdict['passed'] => 'passed',
                default => 'failed',
            },
            'checked_at' => $verdict['at'] ?? null,
        ];

        /*
         * The summary names compose services and the hosts the sandbox
         * could not reach, so it is for an operator and not for the
         * internet. Included only when the test failed, where it is the
         * difference between a red light and a fix.
         */
        if ($verdict !== null && ! $verdict['passed']) {
            $body['detail'] = $verdict['summary'];
        }

        $healthy = ! $policy->buildsEnabled || ($verdict !== null && $verdict['passed']);

        return response()
            ->json($body)
            ->setStatusCode($healthy ? 200 : 503)
            ->header('Cache-Control', 'no-store');
    }
}
