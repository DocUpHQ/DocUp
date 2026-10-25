<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Automation;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\AccessLevel;
use App\Builds\PathGlob;
use App\Builds\SafePattern;
use App\Models\AutomationRule;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Versions\SyncOutcome;
use App\Versions\VersionOperations;
use App\Webhooks\PushEvent;

/**
 * §8.6.8's automation rules.
 *
 * > "The system MUST support automation rules triggered by version
 * > **creation or disappearance**: activate, hide, make public or private,
 * > set as default, or trigger a build — filtered by branch/tag regex,
 * > changed-path globs, commit message or PR label. 🛑 These rules are the
 * > mechanism that makes a monorepo feeding N projects tractable; without
 * > them every push rebuilds everything."
 *
 * 🛑 **Nothing here calls {@see VersionOperations::delete()} except through
 * a `delete_version` rule on `version_disappeared`.** §8.6.15 is categorical:
 * "Nothing may delete reader-visible URLs without either an explicit rule or
 * an explicit action." The pairing is enforced on write
 * ({@see AutomationAction::isValidFor()}) and again here, because a row
 * written before that validation existed — by a migration, by a restore, by
 * a hand-edited database — must not be able to delete a reader's URLs
 * either.
 */
final readonly class AutomationEngine
{
    public function __construct(
        private VersionOperations $versions,
        private ?BuildRequestSink $builds = null,
    ) {}

    /**
     * Fire every matching rule for one sync's outcome.
     *
     * @param  PushEvent|null  $event  the push that caused the sync, where there was one
     * @param  string|null  $actorId  raw 16 bytes
     * @return list<FiredRule> what fired, in order, for the audit trail and the tests
     */
    public function apply(
        Project $project,
        SyncOutcome $outcome,
        ?PushEvent $event = null,
        ?string $actorId = null,
    ): array {
        $fired = [];

        foreach ($outcome->created as $version) {
            foreach ($this->run($project, $version, AutomationTrigger::VersionCreated, $event, $actorId) as $entry) {
                $fired[] = $entry;
            }
        }

        foreach ($outcome->disappeared as $version) {
            foreach ($this->run($project, $version, AutomationTrigger::VersionDisappeared, $event, $actorId) as $entry) {
                $fired[] = $entry;
            }
        }

        return $fired;
    }

    /**
     * @return list<FiredRule>
     */
    private function run(
        Project $project,
        ProjectVersion $version,
        AutomationTrigger $trigger,
        ?PushEvent $event,
        ?string $actorId,
    ): array {
        $rules = AutomationRule::query()
            ->where('project_id', $project->id)
            ->where('trigger', $trigger->value)
            ->where('enabled', true)
            ->orderBy('position')
            ->get();

        $fired = [];

        foreach ($rules as $rule) {
            if (! $rule->actionSuitsTrigger()) {
                // A row that predates the validation, or one a restore
                // brought back. Passed over rather than run: see the class
                // note for why this matters for `delete_version`.
                continue;
            }

            if (! $this->matches($rule, $version, $event)) {
                continue;
            }

            $this->fire($rule, $project, $version, $actorId);
            $fired[] = new FiredRule($rule, $version);

            /*
             * 🛑 First match wins unless the operator opted in, because
             * §8.6.8's actions are not all commutative: `set_default`
             * followed by `delete_version` leaves a project pointing at
             * nothing, and `make_private` followed by `build` builds a
             * version whose visibility just changed under it.
             */
            if (! $rule->continue_matching) {
                break;
            }

            /*
             * A rule that deleted the version ends the chain whatever the
             * flag says: everything after it would operate on a row that no
             * longer exists.
             */
            if ($rule->action === AutomationAction::DeleteVersion) {
                break;
            }
        }

        return $fired;
    }

    private function matches(AutomationRule $rule, ProjectVersion $version, ?PushEvent $event): bool
    {
        if ($rule->ref_kind !== 'any' && $version->ref_kind !== $rule->ref_kind) {
            return false;
        }

        if ($rule->ref_pattern !== null) {
            $name = $version->ref_name ?? $version->slug;

            if (! SafePattern::matches($rule->ref_pattern, $name)) {
                return false;
            }
        }

        /*
         * 🛑 The path and message filters need a push to read, and a sync
         * from an `ls-remote` poll or a manual re-scan has none. A rule
         * carrying one of them does NOT match in that case — it is not
         * "no filter", it is "the filter cannot be evaluated", and
         * treating an unevaluable filter as satisfied would make a
         * `make_public` rule fire on a poll that was never meant to trigger
         * it.
         */
        if ($rule->path_globs !== null && $rule->path_globs !== []) {
            if (! $event instanceof PushEvent || ! $event->changedPathsAreTrustworthy()) {
                return false;
            }

            if (! PathGlob::anyMatches($rule->path_globs, $event->changedPaths)) {
                return false;
            }
        }

        if ($rule->commit_message_pattern !== null) {
            if (! $event instanceof PushEvent) {
                return false;
            }

            if (! SafePattern::matches($rule->commit_message_pattern, $event->commitMessageBlob())) {
                return false;
            }
        }

        if ($rule->pr_label !== null) {
            if (! $event instanceof PushEvent || ! in_array($rule->pr_label, $event->labels, true)) {
                return false;
            }
        }

        return true;
    }

    private function fire(AutomationRule $rule, Project $project, ProjectVersion $version, ?string $actorId): void
    {
        match ($rule->action) {
            AutomationAction::Activate => $this->versions->setActive([$version], true, $actorId),
            AutomationAction::Deactivate => $this->versions->setActive([$version], false, $actorId),

            // §8.6.2's `listed`. 🛑 Hidden is not private: the version still
            // serves by direct URL, and only the flyout, sitemap, llms.txt
            // and search lose it.
            AutomationAction::Hide => $this->setListed($version, false),
            AutomationAction::Show => $this->setListed($version, true),

            AutomationAction::MakePublic => $this->setVisibility($version, AccessLevel::Public),
            AutomationAction::MakePrivate => $this->setVisibility($version, AccessLevel::Restricted),

            AutomationAction::SetDefault => $this->setDefault($project, $version),
            AutomationAction::Build => $this->builds?->requestBuild($version, 'repository_fanout'),
            AutomationAction::DeleteVersion => $this->versions->delete($version, $actorId),
        };

        $rule->forceFill(['last_fired_at' => now()])->save();

        Audit::record(
            action: 'automation.rule.fired',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $project->organisation_id,
            actorId: $actorId,
            subjectType: 'project_version',
            subjectId: $version->id,
            ruleId: $rule->id,
            payload: [
                'rule' => $rule->label,
                'position' => $rule->position,
                'action' => $rule->action->value,
                'trigger' => $rule->trigger->value,
            ],
        );
    }

    private function setListed(ProjectVersion $version, bool $listed): void
    {
        $version->forceFill(['listed' => $listed])->save();
    }

    /**
     * 🛑 §8.6.3's latch is NOT cleared by `make_public`.
     *
     * > "A newly discovered version MUST inherit `private` whenever the
     * > project has ever had a non-public access rule, so that making a
     * > project public can never retroactively expose a version."
     *
     * **Ever.** A rule that made one version public must not make the next
     * branch be born public too, so `has_ever_been_guarded` is set when a
     * version goes private here and never unset when one goes public.
     */
    private function setVisibility(ProjectVersion $version, AccessLevel $level): void
    {
        $version->forceFill(['visibility' => $level->value])->save();

        if ($level === AccessLevel::Public) {
            return;
        }

        $project = $version->project;

        if ($project instanceof Project && $project->has_ever_been_guarded !== true) {
            $project->forceFill(['has_ever_been_guarded' => true])->save();
        }
    }

    private function setDefault(Project $project, ProjectVersion $version): void
    {
        $project->forceFill(['default_version_id' => $version->id])->save();
    }
}
