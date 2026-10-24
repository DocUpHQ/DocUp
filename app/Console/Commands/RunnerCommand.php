<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Builds\Runner\CgroupSampler;
use App\Builds\Runner\IsolationSelfTest;
use App\Builds\Runner\RunnerDriver;
use App\Builds\Runner\RunOutcome;
use App\Builds\Runner\Spool;
use App\Builds\RunSpecification;
use Illuminate\Console\Command;

/**
 * The runner process (§8.5.13).
 *
 * > "No request-handling or queue-worker process MUST hold a container-runtime
 * > socket. The runner is the sole holder, and it MUST accept only a typed run
 * > specification rendered through a fixed argv template."
 *
 * 🛑 **This process has no database credentials and no `APP_KEY`**, which is
 * one of Phase 06's exit criteria and is asserted by
 * `RunnerIsolationTest`. It follows that it can do nothing except what a
 * specification in the spool tells it to, and that a compromise of the one
 * process holding the Docker socket yields no tenant data, no envelope key
 * and no way to reach the database.
 *
 * It also means this command must never touch the database, and that is
 * easier to get wrong than it looks: a single `Model::find()` added later
 * would work on a developer's machine, where everything shares one
 * environment, and fail in production with a connection error nobody expects.
 * The architecture test asserts the absence rather than trusting the absence.
 */
final class RunnerCommand extends Command
{
    protected $signature = 'docup:runner
        {--once : claim at most one job and exit, for tests and for `doctor`}
        {--max-jobs=0 : stop after this many jobs (0 means run until stopped)}';

    protected $description = 'Run build containers from the spool (SPEC 8.5.13). Holds the runtime socket; holds no credentials.';

    public function handle(RunnerDriver $driver, Spool $spool, IsolationSelfTest $selfTest): int
    {
        $spool->ensure();

        $swept = $driver->sweep();

        if ($swept > 0) {
            $this->warn("removed {$swept} container(s) left by a previous runner");
        }

        /*
         * 🛑 §8.5.12: "Network isolation MUST be verified at boot by
         * launching a throwaway container … **Startup MUST fail** if the
         * self-test fails."
         *
         * It runs HERE, in the runner, because the runner is the only
         * process that holds the container-runtime socket (§8.5.13) and so
         * the only one that *can* launch the throwaway container. A
         * non-zero exit is how "startup fails" is expressed to an init
         * system: compose reports the service as failed rather than
         * starting a runner that would accept builds into a sandbox nobody
         * has checked.
         *
         * The verdict is also written to the spool, because the worker and
         * the dashboard need to say "builds are unavailable" and cannot ask
         * this process anything — it has no database.
         */
        /*
         * 🛑 Said out loud, because the alternative is losing a control in
         * silence. Without the cgroup hierarchy mounted (§8.5.15), the OOM
         * and PID counters read zero rather than failing — so a fork bomb
         * looks like a clean build and an OOM-killed subprocess looks like
         * nothing at all. Found when CI's sandbox job reported the
         * fork-bomb exit criterion as `succeeded`.
         */
        if (! CgroupSampler::hierarchyIsVisible()) {
            $this->warn(
                '§8.5.15: the cgroup hierarchy is not visible at '
                .(string) config('builds.sandbox.cgroup_root')
                .', so OOM kills and PID-ceiling hits cannot be read authoritatively. '
                .'Builds will still run; a fork bomb will not be detected. Mount '
                .'/sys/fs/cgroup read-only, as compose.yaml does.',
            );
        }

        $result = $selfTest->run();
        $spool->writeSelfTest($result->passed, $result->summary);

        if (! $result->passed) {
            $this->error('§8.5.12 sandbox isolation self-test FAILED — refusing to start.');
            $this->line($result->summary);

            if (! $result->available) {
                $this->line('');
                $this->line('The sandbox is not configured on this host. The runner needs the');
                $this->line('egress proxy and the sandboxes network from compose.yaml; without');
                $this->line('them a build would run with an isolation nobody has verified.');
            }

            return self::FAILURE;
        }

        $this->info('§8.5.12 sandbox isolation self-test passed — '.$result->summary);
        $this->info('runner ready — spool '.$spool->root());

        $interval = max(50, (int) config('builds.poll_interval_ms')) * 1000;
        $maxJobs = (int) $this->option('max-jobs');
        $handled = 0;

        while (true) {
            $claim = $spool->claimNext();

            if ($claim === null) {
                if ($this->option('once')) {
                    return self::SUCCESS;
                }

                usleep($interval);

                continue;
            }

            [$jobId, $spec] = $claim;
            $this->line("running {$jobId}");

            /*
             * 🛑 One job's failure must never take the runner down with it.
             *
             * Without this the first unexpected error — a `PharData` that
             * disliked a filename, in the case that produced this comment —
             * killed the process, left the job sitting in `claimed/` where
             * nothing would reclaim it, and left the worker waiting out its
             * whole timeout for an answer that could not arrive. The worker
             * then reported `infra.runner_did_not_answer`, which is true and
             * tells nobody what happened.
             *
             * Every outcome, including an unexpected one, now comes back as
             * a result the worker can classify and an operator can read.
             */
            try {
                $result = $this->runJob($driver, $spool, $jobId, $spec);
            } catch (\Throwable $unexpected) {
                $result = RunOutcome::rejected($unexpected::class.': '.$unexpected->getMessage())->toArray();

                $this->error("{$jobId} failed unexpectedly: ".$unexpected->getMessage());
            }

            $spool->writeResult($jobId, $result);
            $handled++;

            if ($this->option('once') || ($maxJobs > 0 && $handled >= $maxJobs)) {
                return self::SUCCESS;
            }
        }
    }

    /**
     * Run one job and return the result document.
     *
     * Named `runJob` rather than `execute`, which is Symfony's own protected
     * hook on `Command` — a private method of that name is a fatal error at
     * class-load time, not a subtle bug, but it is the kind of collision
     * that only shows up when the process actually starts.
     *
     * @return array<string, mixed>
     */
    private function runJob(RunnerDriver $driver, Spool $spool, string $jobId, RunSpecification $spec): array
    {
        /*
         * The workspace is created before every container rather than once
         * per build. `docker volume create` on a volume that exists is a
         * no-op, and making each run self-sufficient means the stages have
         * no ordering requirement between runners — which matters the moment
         * there is more than one.
         */
        $driver->createWorkspace($spec->buildId);

        /*
         * 🛑 Taken and removed in one call, before the container starts. The
         * runner holds it in memory for the length of one `fwrite` into the
         * container's stdin and never writes it anywhere.
         */
        $outcome = $driver->run($spec, $spool->takeCredential($jobId));
        $result = $outcome->toArray();

        if ($outcome->succeeded() && $spec->exportPath !== null) {
            $exported = $driver->exportDirectory($spec->volume, $spec->exportPath, $spool->output($jobId));

            /*
             * 🛑 A missing output directory is §8.4.5's contract failure, not
             * an infrastructure error. The distinction decides whether
             * §8.5.16 retries (it must not — the next attempt produces the
             * same empty directory) and whether §8.5.17 counts it toward the
             * governor (it does, because the author can fix it).
             */
            if (! $exported) {
                $result['failure_class'] = 'contract';
                $result['failure_reason'] = 'no_output_directory';
            }
        }

        if ($spec->releaseWorkspace) {
            $driver->destroyWorkspace($spec->volume);
        }

        return $result;
    }
}
