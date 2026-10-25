<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Auth\OrganisationContext;
use App\Automation\CronSchedule;
use App\Builds\BuildTrigger;
use App\Builds\Jobs\RunBuild;
use App\Models\BuildSchedule;
use App\Models\Project;
use App\Models\ProjectVersion;
use Carbon\CarbonImmutable;
use Illuminate\Console\Command;

/**
 * `docup:schedules:run` — §8.5.3's "native per-version cron schedule".
 *
 * Runs every minute from the scheduler and fires whatever is due. The cron
 * arithmetic and §8.22.13's DST semantics live in
 * {@see CronSchedule}; this command is the part that reads
 * the database, so that the semantics can be tested without a clock and the
 * clock can be tested without a database.
 *
 * 🛑 **Due is `next_run_at <= now`, not "the expression matches this
 * minute".** A scheduler that was down for ten minutes would otherwise skip
 * every schedule it missed, silently, and the operator's nightly build
 * would simply not have happened — which is the failure a nightly build
 * exists to prevent. Reading a stored instant means a late tick still fires
 * once.
 */
final class RunSchedulesCommand extends Command
{
    protected $signature = 'docup:schedules:run
        {--dry-run : Report what would fire without firing it}
        {--json : Machine-readable output}';

    protected $description = 'Fire the SPEC 8.5.3 build schedules that are due';

    public function handle(OrganisationContext $context, BuildTrigger $trigger): int
    {
        $dryRun = $this->option('dry-run') === true;
        $now = CarbonImmutable::now();

        /*
         * Installation-wide by declaration. Schedules belong to every
         * tenant and §8.2.1's context throws rather than defaulting, so a
         * command that spans tenants says so.
         */
        $context->spanAllOrganisations();

        /** @var list<BuildSchedule> $due */
        $due = array_values(
            BuildSchedule::query()
                ->where('enabled', true)
                ->whereNotNull('next_run_at')
                ->where('next_run_at', '<=', $now)
                ->orderBy('next_run_at')
                ->get()
                ->all(),
        );

        $fired = 0;
        $skipped = 0;

        foreach ($due as $schedule) {
            $version = $this->versionFor($schedule);

            if (! $version instanceof ProjectVersion) {
                /*
                 * A schedule whose version is gone, or whose project has no
                 * default version. Advanced rather than left due, so it
                 * does not re-appear in this query every minute for ever —
                 * and left enabled, because §8.6.14 re-points the default
                 * pointer and the schedule should start working again when
                 * it does.
                 */
                $schedule->advance($now);
                $skipped++;

                continue;
            }

            if ($dryRun) {
                $this->line('would fire: '.bin2hex($schedule->id).' -> '.$version->slug);
                $fired++;

                continue;
            }

            $request = $trigger->record(version: $version, trigger: 'schedule');

            if (! $request->isTerminal()) {
                RunBuild::dispatch($request->id);
                $fired++;
            } else {
                $skipped++;
            }

            $schedule->advance($now);
        }

        if ($this->option('json') === true) {
            $this->line((string) json_encode([
                'due' => count($due),
                'fired' => $fired,
                'skipped' => $skipped,
            ], JSON_THROW_ON_ERROR));

            return self::SUCCESS;
        }

        $this->info(sprintf('%d due, %d fired, %d skipped', count($due), $fired, $skipped));

        return self::SUCCESS;
    }

    /**
     * The version a schedule builds.
     *
     * 🛑 A null `project_version_id` means "the default version", resolved
     * at fire time rather than written down. §8.6.14 re-points the default
     * pointer automatically when its target is deleted or deactivated, and
     * a schedule that had captured the old id would go on building a
     * version nobody reads.
     */
    private function versionFor(BuildSchedule $schedule): ?ProjectVersion
    {
        if ($schedule->project_version_id !== null) {
            $version = $schedule->version;

            return $version instanceof ProjectVersion ? $version : null;
        }

        $project = $schedule->project;

        if (! $project instanceof Project || $project->default_version_id === null) {
            return null;
        }

        return ProjectVersion::query()->find($project->default_version_id);
    }
}
