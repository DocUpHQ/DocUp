<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Readers\Containment;
use Illuminate\Console\Command;

/**
 * `docup:containment` — the application's half of §8.12.22's containment proof.
 *
 * 🛑 **It does not fetch anything, and that is the design**, not a limitation.
 * §8.12.22 asks for a check that fetches "through the real edge", which means an
 * HTTP request leaving the application; §8.3.9 routes every outbound request
 * through the one `HardenedEgressClient`, which denies private and loopback
 * addresses — every address the edge has — and the architecture test enforcing
 * that allows one exemption with a note saying an allowlist growing by one
 * legitimate case per phase stops being a gate.
 *
 * So `deploy/containment-self-test.sh` does the fetching with `curl` and this
 * command is what it talks to:
 *
 *   `--plan`    prints the host and path of a known-private asset, or
 *               `state=not_applicable` when the installation has nothing
 *               private published.
 *   `--record`  stores what the probe saw and exits non-zero on a failure, so
 *               the script's exit status is the application's verdict rather
 *               than the script's own opinion.
 *
 * 🛑 Written as a plain name rather than `{@see}`, because Pint's
 * `fully_qualified_strict_types` fixer turns a `{@see}` reference into a real
 * `use` statement — and the Pest `laravel` preset then refuses a console
 * command depending on an HTTP controller, correctly. The reference is worth
 * keeping; the import is not.
 *
 * `App\Http\Controllers\Health\SelfTestController` reports the verdict at
 * §8.1.10's `/_/health/self-test`, and `docup:doctor` refuses to pass without
 * one.
 */
final class ContainmentCommand extends Command
{
    protected $signature = 'docup:containment
        {--plan : Print the host and path of a known-private asset to probe}
        {--record : Store a verdict; requires --status}
        {--status= : The status the edge answered with no credentials}
        {--host= : The host that was probed, for the verdict}
        {--negative= : The status the edge answered WITH credentials, when the probe tested both halves}';

    protected $description = 'Plan and record §8.12.22’s private-asset containment self-test';

    public function handle(Containment $containment): int
    {
        if ($this->option('plan')) {
            return $this->plan($containment);
        }

        if ($this->option('record')) {
            return $this->record($containment);
        }

        /* Neither flag: report what is known, which is what an operator wants. */
        $this->line('state='.$containment->state());

        $verdict = $containment->verdict();

        if ($verdict !== null) {
            $this->line('status='.$verdict['status']);
            $this->line('summary='.$verdict['summary']);
            $this->line('at='.$verdict['at']);
        }

        return self::SUCCESS;
    }

    private function plan(Containment $containment): int
    {
        $plan = $containment->plan();

        if ($plan === null) {
            /*
             * 🛑 Exit **zero** with `not_applicable`. An installation serving
             * only public documentation has nothing to probe, and a non-zero
             * exit here would make the boot script fail on a correct
             * installation — which is how a self-test gets commented out.
             */
            $this->line('state=not_applicable');

            return self::SUCCESS;
        }

        $this->line('host='.$plan['host']);
        $this->line('path='.$plan['path']);

        return self::SUCCESS;
    }

    private function record(Containment $containment): int
    {
        $status = $this->option('status');

        if (! is_string($status) || ! is_numeric($status)) {
            $this->error('--record needs a numeric --status');

            return self::FAILURE;
        }

        $code = (int) $status;
        $host = is_string($this->option('host')) ? $this->option('host') : null;

        /*
         * 🛑 §8.12.22's own sentence: "**fails on any 200**". Not "expects a
         * 404" — a 401 or a 403 does not serve the document either, and §8.12.23
         * permits both in narrow cases. What is forbidden is the bytes.
         */
        $passed = $code !== 200;

        $negative = $this->option('negative');
        $summary = $passed
            ? 'anonymous request refused with '.$code
            : '🛑 a known-private asset served 200 with no credentials';

        /*
         * 🛑 The negative control, which is what Phase 22 adds to Phase 21's
         * half. A probe that only ever sees a refusal cannot tell containment
         * from a broken edge: an installation whose documentation host is
         * misconfigured refuses *everything*, and the positive half would pass
         * on it forever. So the script may also fetch the same asset **with**
         * a reader session, and a 200 there is what proves the refusal was a
         * decision rather than an outage.
         */
        if (is_string($negative) && is_numeric($negative)) {
            $credentialed = (int) $negative;

            if ($credentialed !== 200) {
                $passed = false;
                $summary = '🛑 the negative control failed: a credentialed read answered '
                    .$credentialed.', so the refusal proves nothing';
            } else {
                $summary .= '; credentialed read served 200';
            }
        }

        $containment->record($passed, $code, $summary, $host);

        $this->line('state='.($passed ? 'passed' : 'failed'));
        $this->line('summary='.$summary);

        return $passed ? self::SUCCESS : self::FAILURE;
    }
}
