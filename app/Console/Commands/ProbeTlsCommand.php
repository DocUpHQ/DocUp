<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Models\Domain;
use App\Tls\TlsProbe;
use App\Tls\TlsProber;
use Illuminate\Console\Command;

/**
 * `docup:tls:probe` — §8.10.17's six-hourly handshake prober.
 *
 * 🛑 This command is the **only** thing in the installation that can notice
 * an issuance failure. §8.10.17 is explicit that "the proxy never calls the
 * permission endpoint back on issuance failure", so a domain whose
 * certificate the CA refused looks, from every table and every screen,
 * exactly like one that is working — until a reader reports a TLS error.
 *
 * It follows that a scheduler which is not running turns this from a safety
 * net into nothing at all, silently. `docup:doctor` reports the scheduler
 * for that reason, which is the check Phase 11 added after finding that
 * nothing in the compose file had ever run `schedule:work`.
 */
final class ProbeTlsCommand extends Command
{
    protected $signature = 'docup:tls:probe {--host= : Probe one hostname instead of every active domain}';

    protected $description = 'Handshake with every serving domain and record expiry, issuer and error (§8.10.17)';

    public function handle(TlsProber $prober): int
    {
        $host = $this->option('host');

        $probes = is_string($host) && $host !== ''
            ? $this->one($prober, $host)
            : $prober->run();

        $failed = 0;

        foreach ($probes as $probe) {
            if ($probe->ok()) {
                $this->components->twoColumnDetail(
                    $probe->host,
                    $probe->issuer.' until '.$probe->notAfter?->toDateString(),
                );

                continue;
            }

            $failed++;
            $this->components->twoColumnDetail($probe->host, '<fg=red>'.$probe->error.'</>');
        }

        if ($probes === []) {
            $this->components->info('No domain is currently serving.');
        }

        /*
         * 🛑 Exit 0 even when a probe failed, and the reason is operational
         * rather than philosophical. This runs from the scheduler; a
         * non-zero exit marks the scheduled task as failed, and a single
         * domain whose owner has taken their DNS down would then report the
         * whole installation's TLS monitoring as broken, every six hours,
         * until somebody muted it. The failures are rows and log lines,
         * which is what an operator can act on one at a time.
         */
        if ($failed > 0) {
            $this->components->warn($failed.' of '.count($probes).' domains failed their handshake; see certificate_issuance_attempts');
        }

        return self::SUCCESS;
    }

    /** @return list<TlsProbe> */
    private function one(TlsProber $prober, string $host): array
    {
        $domain = Domain::query()->where('host', $host)->first();

        if ($domain === null) {
            $this->components->error('No domain row for '.$host.'.');

            return [];
        }

        return [$prober->probe($domain)];
    }
}
