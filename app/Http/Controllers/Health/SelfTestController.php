<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Health;

use App\Builds\Runner\Spool;
use App\Builds\Sandbox\SandboxPolicy;
use App\Http\Controllers\Controller;
use App\Readers\Containment;
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
 * 🛑 **Phase 22 added §8.12.22's containment assertion**, which this file said
 * it was waiting for — and it arrives on exactly the same terms as the sandbox
 * one. The probe is `deploy/containment-self-test.sh`, because the fetch has to
 * leave the application and come back through the real edge and §8.3.9 gives
 * PHP no way to do that; {@see Containment} explains why at length. This
 * endpoint reports the verdict, and a **missing** verdict on an installation
 * that has something private to probe is reported as a failure for the same
 * reason a missing sandbox verdict is: nothing has checked it.
 */
final class SelfTestController extends Controller
{
    public function __invoke(Spool $spool, SandboxPolicy $policy, Containment $containment): JsonResponse
    {
        $verdict = $spool->readSelfTest();
        $containmentState = $containment->state();
        $containmentVerdict = $containment->verdict();

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
            /*
             * 🛑 §8.12.22's own four states. `not_applicable` is decided from
             * the database — there is genuinely no non-public published project
             * to probe — and never from a flag, because a flag is what an
             * operator sets when the check is inconvenient.
             */
            'private_asset_containment' => $containmentState,
            'containment_checked_at' => $containmentVerdict['at'] ?? null,
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

        if ($containmentVerdict !== null && ! $containmentVerdict['passed']) {
            $body['containment_detail'] = $containmentVerdict['summary'];
        }

        $sandboxHealthy = ! $policy->buildsEnabled || ($verdict !== null && $verdict['passed']);

        /*
         * 🛑 `not_applicable` is healthy; `never_run` is not. An installation
         * with nothing private published has nothing to prove, and one that has
         * something and has never checked it is in the state §8.5.12's note
         * describes — "the same operational fact as a failure".
         */
        $containmentHealthy = in_array($containmentState, ['passed', 'not_applicable'], true);

        $healthy = $sandboxHealthy && $containmentHealthy;

        return response()
            ->json($body)
            ->setStatusCode($healthy ? 200 : 503)
            ->header('Cache-Control', 'no-store');
    }
}
