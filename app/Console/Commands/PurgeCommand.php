<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\Deletions;
use App\Auth\OrganisationContext;
use App\Models\Organisation;
use App\Models\Project;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

/**
 * `docup:purge` — the §8.22.6 mandatory hard purge.
 *
 * 🛑 §8.22.6: "`deleted_at` MUST be a **recovery window, not a state**: a
 * mandatory scheduled hard purge at 30 days, not operator-optional, documented
 * as the erasure latency floor."
 *
 * The reason that word "mandatory" is in the specification: a soft delete that
 * is never hard-purged retains personal data indefinitely while the product
 * tells people it was erased. Thirty days is then the honest answer to "how
 * long until my data is gone", and the number only means anything if something
 * actually runs.
 *
 * So this is scheduled rather than offered, and it reports what it destroyed —
 * a purge job that runs silently is one nobody notices has stopped.
 */
final class PurgeCommand extends Command
{
    protected $signature = 'docup:purge
        {--dry-run : Report what would be destroyed without destroying it}
        {--json : Machine-readable output}';

    protected $description = 'Hard-purge rows past the SPEC 8.22.6 recovery window';

    public function handle(): int
    {
        $cutoff = now()->subDays(Deletions::RECOVERY_WINDOW_DAYS);
        $dryRun = $this->option('dry-run') === true;

        /*
         * Installation-wide by declaration, not by accident. The purge spans
         * every tenant, and §8.2.1's context throws rather than defaulting —
         * so this has to say so, which is exactly the explicitness the context
         * exists to force.
         */
        app(OrganisationContext::class)->spanAllOrganisations();

        $projects = Project::query()
            ->onlyTrashed()
            ->where('deleted_at', '<', $cutoff)
            ->get();

        $organisations = Organisation::query()
            ->onlyTrashed()
            ->where('deleted_at', '<', $cutoff)
            ->get();

        if (! $dryRun) {
            DB::transaction(function () use ($projects, $organisations): void {
                foreach ($projects as $project) {
                    /*
                     * 🛑 The audit event is written BEFORE the row goes, and
                     * the slug reservation is already in place from
                     * Deletions::deleteProject(). Afterwards there would be
                     * nothing left to describe: §8.22.1 retains audit events
                     * past the data they describe, and that is only possible
                     * if the event exists while the subject still does.
                     */
                    Audit::record(
                        action: 'project.purged',
                        actorType: ActorType::System,
                        organisationId: $project->organisation_id,
                        subjectType: 'project',
                        subjectId: $project->id,
                        payload: ['recovery_window_days' => Deletions::RECOVERY_WINDOW_DAYS],
                    );

                    $project->forceDelete();
                }

                foreach ($organisations as $organisation) {
                    Audit::record(
                        action: 'organisation.purged',
                        actorType: ActorType::System,
                        organisationId: $organisation->id,
                        subjectType: 'organisation',
                        subjectId: $organisation->id,
                        payload: ['recovery_window_days' => Deletions::RECOVERY_WINDOW_DAYS],
                    );

                    // Cascades take the organisation's remaining rows. The
                    // slug reservations cascade too — deliberately: §8.2.8
                    // reserves PROJECT slugs, and an organisation that no
                    // longer exists has no namespace to protect.
                    $organisation->forceDelete();
                }
            });
        }

        app(OrganisationContext::class)->forget();

        if ($this->option('json') === true) {
            $this->line((string) json_encode([
                'cutoff' => $cutoff->format('Y-m-d H:i:s'),
                'dry_run' => $dryRun,
                'projects' => $projects->count(),
                'organisations' => $organisations->count(),
            ], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));

            return self::SUCCESS;
        }

        $this->newLine();
        $this->line(sprintf(
            '  %s  %d project%s and %d organisation%s past the %d-day recovery window.',
            $dryRun ? '<fg=yellow>would</>' : '<fg=green>done</> ',
            $projects->count(),
            $projects->count() === 1 ? '' : 's',
            $organisations->count(),
            $organisations->count() === 1 ? '' : 's',
            Deletions::RECOVERY_WINDOW_DAYS,
        ));
        $this->newLine();

        return self::SUCCESS;
    }
}
