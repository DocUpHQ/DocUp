<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Access\PolicyFinding;
use App\Access\PolicyLinter;
use App\Access\PolicyObservation;
use App\Access\ReaderPolicies;
use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\OrganisationContext;
use App\Notifications\PolicyReachabilityChanged;
use App\Support\Uuid;
use Illuminate\Console\Command;

/**
 * `docup:policy:lint` — §8.12.22's nightly policy linter.
 *
 * > "a nightly policy linter that re-validates every active rule and alerts on
 * > reachability changes"
 *
 * {@see PolicyLinter} is the whole of the analysis; this is the schedule, the
 * alert and the exit code. The three are separated because each has a different
 * audience: the analysis answers a question, the mail reaches a person, and the
 * exit code reaches a monitoring system that nobody reads until something is
 * wrong.
 *
 * ## 🛑 Why the exit code is not the alert, and the mail is not the exit code
 *
 * They report **different things**, and conflating them loses one of them:
 *
 * - A non-zero exit means the policy is **broken** — a rule names a binding
 *   that is gone, misclassified or not in service, so the rule refuses everyone
 *   for ever. That is a fault, it will not fix itself, and an operator needs to
 *   know even if nothing changed tonight. See {@see PolicyFinding::isFault()}.
 * - The mail means something **changed**, which is §8.12.22's actual
 *   requirement. A change may be perfectly intended; the operator is the only
 *   one who can say.
 *
 * 🛑 A deliberately-shadowed rule does neither. §8.12.6 gives operators shadow
 * rules on purpose, and failing a nightly job on an intentional configuration
 * is exactly how a nightly job gets switched off — after which §8.12.22's
 * requirement is satisfied by a cron entry and nothing else.
 */
final class PolicyLintCommand extends Command
{
    protected $signature = 'docup:policy:lint
        {--project= : One project UUID, rather than every project with a policy}
        {--quiet-alerts : Analyse and record without notifying anybody}
        {--json : Machine-readable output}';

    protected $description
        = 'Re-validate every reader access rule and alert on reachability changes (SPEC 8.12.22)';

    public function handle(
        PolicyLinter $linter,
        ReaderPolicies $policies,
        OrganisationContext $context,
    ): int {
        /*
         * Installation-wide by declaration. §8.2.1's context raises rather than
         * defaulting, and a scheduled job has no tenant to inherit — which is
         * the property that makes the raise useful rather than annoying.
         */
        $context->spanAllOrganisations();

        $projects = $this->projects($policies);

        if ($projects === []) {
            $this->report([], 0);

            return self::SUCCESS;
        }

        $faults = 0;
        $alerted = 0;
        $lines = [];

        foreach ($projects as $project) {
            $observations = $linter->lint(
                projectId: $project['id'],
                organisationId: $project['organisation_id'],
                authzEpoch: $project['authz_epoch'],
            );

            if ($observations === []) {
                continue;
            }

            $changed = array_values(array_filter(
                $observations,
                static fn (PolicyObservation $observation): bool => $observation->alerts(),
            ));

            $faulty = array_values(array_filter(
                $observations,
                static fn (PolicyObservation $observation): bool => $observation->isFaulty(),
            ));

            $faults += count($faulty);

            foreach ([...$changed, ...$faulty] as $observation) {
                $lines[] = $project['slug'].': '.$observation->summary();
            }

            /*
             * 🛑 The audit row is written for **every** finding, changed or
             * faulty, and before the mail. §20.3's chain is the permanent,
             * tamper-evident record that the installation knew; mail is best
             * effort and an operator can delete it.
             */
            $this->record($project, [...$changed, ...$faulty]);

            if ($changed !== [] && $this->option('quiet-alerts') !== true) {
                PolicyReachabilityChanged::dispatch(
                    $project['organisation_id'],
                    $project['slug'],
                    $changed,
                );

                $alerted++;
            }
        }

        $this->report($lines, $alerted);

        /*
         * 🛑 Non-zero only for a fault. See the class note: a change is for a
         * human to judge and a fault is for a machine to page about.
         */
        return $faults === 0 ? self::SUCCESS : self::FAILURE;
    }

    /**
     * Every project with a reader policy, or the one named.
     *
     * 🛑 Through {@see ReaderPolicies}, never by querying `reader_policies`
     * here. §17's Phase 21 exit criterion is "the architecture test fails when
     * a second class reads the policy tables", and the reason is §8.12.6's
     * first-match-wins: it is "not what anybody writes by accident", so there
     * is exactly one place that reads the rows and turns them into rules.
     *
     * @return list<array{id: string, organisation_id: string, slug: string, authz_epoch: int}>
     */
    private function projects(ReaderPolicies $policies): array
    {
        $one = $this->option('project');

        if (! is_string($one) || $one === '') {
            return $policies->projectsWithAPolicy();
        }

        $bytes = Uuid::tryToBytes($one);

        if ($bytes === null) {
            $this->components->error('--project takes a project UUID');

            return [];
        }

        return $policies->projectsWithAPolicy($bytes);
    }

    /**
     * One audit row per finding, naming the rule and the code.
     *
     * @param  array{id: string, organisation_id: string, slug: string, authz_epoch: int}  $project
     * @param  list<PolicyObservation>  $observations
     */
    private function record(array $project, array $observations): void
    {
        foreach ($observations as $observation) {
            foreach ([...$observation->changes, ...$observation->findings] as $finding) {
                if (! $finding->alerts() && ! $finding->isFault()) {
                    continue;
                }

                Audit::record(
                    action: $finding->auditAction(),
                    /*
                     * 🛑 `System`, because nobody did this. The *edit* that
                     * caused it has its own row with its own actor; this row
                     * says the installation noticed, which is a different fact
                     * and one §8.12.22 is specifically asking for.
                     */
                    actorType: ActorType::System,
                    organisationId: $project['organisation_id'],
                    subjectType: 'reader_policy_rule',
                    subjectId: Uuid::toBytes($observation->ruleId),
                    reasonCode: $finding->value,
                    ruleId: Uuid::toBytes($observation->ruleId),
                    payload: [
                        /* §8.22.5: identifiers and codes. The label is the operator's own text. */
                        'project' => Uuid::toText($project['id']),
                        'position' => $observation->position,
                        'reachable' => $observation->reachable,
                        'shadowed_by' => $observation->shadowedBy,
                    ],
                );
            }
        }
    }

    /**
     * @param  list<string>  $lines
     */
    private function report(array $lines, int $alerted): void
    {
        if ($this->option('json') === true) {
            $this->line((string) json_encode([
                'findings' => $lines,
                'projects_alerted' => $alerted,
            ], JSON_PRETTY_PRINT));

            return;
        }

        if ($lines === []) {
            $this->components->info('No reachability changes and no broken rules.');

            return;
        }

        foreach ($lines as $line) {
            $this->line($line);
        }

        $this->newLine();
        $this->components->warn($alerted.' project(s) notified.');
    }
}
