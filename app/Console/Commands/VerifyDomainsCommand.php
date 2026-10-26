<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Domains\DomainVerifier;
use App\Domains\Reverification;
use Illuminate\Console\Command;

/**
 * `docup:domains:verify` — §8.10.6's daily re-verification.
 *
 * 🛑 Scheduled, and the scheduler has to actually be running. Phase 11's
 * build log records finding that nothing in the compose file ever ran
 * `schedule:work`, so §8.22.1's audit anchor had never fired in a
 * deployment; the same hole here would mean a hostname whose DNS was
 * withdrawn keeps serving for ever. `docup:doctor` reports the scheduler,
 * which is the check that makes this command's absence visible.
 *
 * Re-verification is **not** what suspends a domain on its own: it runs one
 * check per due domain and {@see Reverification} decides what that means,
 * including the case where no resolver answered and nothing should move.
 */
final class VerifyDomainsCommand extends Command
{
    protected $signature = 'docup:domains:verify
        {--limit= : Check at most this many domains}
        {--purge : Also drop verification events past the 400-day retention}';

    protected $description = "Re-verify custom domains' DNS proof (§8.10.6)";

    public function handle(): int
    {
        $limit = $this->option('limit');

        $tally = (new Reverification(DomainVerifier::fromConfig()))->run(
            is_numeric($limit) ? (int) $limit : null,
        );

        foreach ($tally as $label => $count) {
            $this->components->twoColumnDetail(ucfirst($label), (string) $count);
        }

        if ($this->option('purge')) {
            $this->components->twoColumnDetail(
                'Purged events',
                (string) DomainVerifier::purge(),
            );
        }

        /*
         * 🛑 Zero, even when domains were suspended. A non-zero exit from a
         * scheduled job means "this job is broken"; a suspended domain means
         * "an operator's DNS is broken", and conflating them would have the
         * scheduler's own alerting fire for somebody else's zone.
         */
        return self::SUCCESS;
    }
}
