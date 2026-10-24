<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Models\Build;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Notifications\BuildFailed;
use App\Notifications\WebhookTriggeringDisabled;
use Illuminate\Support\Facades\DB;

/**
 * §8.5.17's consecutive-failure governor.
 *
 * > "🛑 Only user-caused classes (`user`, `config`, `contract`,
 * > `conflict`, `resource`) MUST count toward the consecutive-failure
 * > governor that disables **webhook** triggering (never manual) after 25
 * > consecutive default-version failures. Infrastructure failures MUST
 * > NEVER disable a tenant."
 *
 * 🛑 **Three separate rules, and each is easy to get wrong in a way that
 * is invisible until it bites somebody:**
 *
 * 1. **Only user-caused classes count.** The set is quoted, not inferred —
 *    `resource` counts (a build asking for more memory than it may have is
 *    the tenant's doing) and `source` does not (a repository that vanished
 *    is usually a permissions change at the provider).
 * 2. **Only the default version.** A project with forty feature branches
 *    failing is not a project to disable; the version its readers see is.
 * 3. **Webhooks only, never manual.** The point of the governor is to stop
 *    an automated loop, not to lock an author out of fixing it. A tenant
 *    who cannot press Build cannot clear the condition that disabled them.
 *
 * 🛑 And infrastructure failures neither increment nor **reset**. Resetting
 * would be the intuitive thing and it is wrong: our own outage would
 * launder somebody's twenty-four consecutive broken configurations back to
 * zero.
 */
final class BuildGovernor
{
    /**
     * Record a terminal build and apply §8.5.17.
     *
     * Called once per build, from the pipeline, after the state is final.
     */
    public function record(Build $build): void
    {
        $version = $build->projectVersion;

        if (! $version instanceof ProjectVersion) {
            return;
        }

        $project = $version->project;

        if (! $project instanceof Project) {
            return;
        }

        $failure = $this->failureClassOf($build);

        /*
         * 🛑 §8.18.2: "Build-failure email MUST exist. Read the Docs mails
         * on every failed build of a tracked version, and a migrating team
         * notices its absence within a day."
         *
         * Every failed build, not only the one that trips the governor,
         * and before the default-version filter below — a failing feature
         * branch is still something its author asked to be told about.
         */
        if ($failure !== null && $failure->isAuthorActionable()) {
            $this->notify($project, new BuildFailed($build, $project, $version));
        }

        // 🛑 Rule 2: the governor counts the DEFAULT version and nothing else.
        if (! $this->isDefaultVersion($project, $version)) {
            return;
        }

        if ($failure === null) {
            $this->reset($project);

            return;
        }

        // 🛑 Rules 1 and the no-reset half: an infrastructure failure
        // changes nothing at all.
        if (! $failure->countsTowardGovernor()) {
            return;
        }

        $count = $project->consecutive_build_failures + 1;
        $threshold = BuildConfig::positiveInt('governor_threshold', 25);

        $project->forceFill(['consecutive_build_failures' => $count])->save();

        if ($count <= $threshold || $project->webhook_triggering_disabled_at !== null) {
            return;
        }

        $this->disableWebhookTriggering($project, $build, $count);
    }

    /**
     * 🛑 Whether a webhook may trigger a build for this project.
     *
     * The one question the rest of the system asks the governor. Manual
     * and API triggers never consult it, which is §8.5.17's "never
     * manual" expressed as the absence of a call rather than as a comment.
     */
    public function permitsWebhookTrigger(Project $project): bool
    {
        return $project->webhook_triggering_disabled_at === null;
    }

    /**
     * Re-enable after a human has looked at it.
     *
     * Resets the counter too: leaving it at 26 would mean the next single
     * failure disabled the project again, which turns a governor into a
     * trap.
     */
    public function reenableWebhookTriggering(Project $project, ?string $actorId = null): void
    {
        if ($project->webhook_triggering_disabled_at === null) {
            return;
        }

        DB::transaction(function () use ($project, $actorId): void {
            $project->forceFill([
                'webhook_triggering_disabled_at' => null,
                'consecutive_build_failures' => 0,
            ])->save();

            Audit::record(
                action: 'project.webhook_triggering.reenabled',
                actorType: $actorId === null ? ActorType::System : ActorType::User,
                organisationId: $project->organisation_id,
                actorId: $actorId,
                subjectType: 'project',
                subjectId: $project->id,
            );
        });
    }

    private function reset(Project $project): void
    {
        if ($project->consecutive_build_failures === 0) {
            return;
        }

        $project->forceFill(['consecutive_build_failures' => 0])->save();
    }

    private function disableWebhookTriggering(Project $project, Build $build, int $count): void
    {
        DB::transaction(function () use ($project, $build, $count): void {
            $project->forceFill(['webhook_triggering_disabled_at' => now()])->save();

            Audit::record(
                action: 'project.webhook_triggering.disabled',
                actorType: ActorType::System,
                organisationId: $project->organisation_id,
                subjectType: 'project',
                subjectId: $project->id,
                payload: [
                    'consecutive_failures' => $count,
                    'threshold' => BuildConfig::positiveInt('governor_threshold', 25),
                    'last_build' => bin2hex($build->id),
                    'last_identifier' => $build->failure_identifier,
                ],
            );
        });

        $this->notify($project, new WebhookTriggeringDisabled($project, $count, $build));
    }

    private function isDefaultVersion(Project $project, ProjectVersion $version): bool
    {
        return is_string($project->default_version_id)
            && $project->default_version_id === $version->id;
    }

    private function failureClassOf(Build $build): ?FailureClass
    {
        if (in_array($build->state, ['published', 'success_unpublished'], true)) {
            return null;
        }

        return is_string($build->failure_class) ? FailureClass::tryFrom($build->failure_class) : null;
    }

    /**
     * Send to whoever owns the project.
     *
     * 🛑 §8.18.1's full subscription model is Phase 33's; this is §8.18.2's
     * floor, and it is deliberately the narrowest thing that satisfies it —
     * the people holding an administrative role over the project or its
     * organisation. Guessing wider would mail an organisation's whole
     * membership about one broken branch, which is how a notification
     * system teaches people to filter it out before it is finished.
     */
    private function notify(Project $project, mixed $notification): void
    {
        foreach (ProjectOwners::of($project) as $user) {
            $user->notify($notification);
        }
    }
}
