<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Auth\OrganisationContext;
use App\Auth\Providers\Bindings;
use App\Auth\Providers\BindingState;
use App\Support\Uuid;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

/**
 * `docup:auth:probe` — §8.12.19's automated half, run on demand or on a clock.
 *
 * > "Bindings MUST progress `draft → verifying → active → degraded →
 * > disabled`, and MUST NOT leave `verifying` until an automated probe passes
 * > **and** a human completes a test login."
 *
 * 🛑 **A probe can move a binding and the moves are deliberate**, which is why
 * this command is not read-only:
 *
 * - `active` → `degraded` after {@see BindingState::DEGRADE_AFTER_FAILURES}
 *   consecutive failures, because a provider that has failed five times is
 *   denying readers whether or not anybody has noticed;
 * - `degraded` → `verifying` on a pass, because a recovered provider should
 *   not stay broken — but **not** to `active`, because §8.12.19 needs a human
 *   test login and a probe is not one.
 *
 * 🛑 It never moves anything **to** `active`. That transition requires the
 * human half, and a command that could skip it would be the whole requirement
 * defeated by a cron entry.
 */
final class AuthProbeCommand extends Command
{
    protected $signature = 'docup:auth:probe
        {binding? : A binding id or name; omit to probe every one}
        {--json : Machine-readable output}
        {--check : Exit non-zero if any probe fails}';

    protected $description = 'Probe authentication bindings and record the verdict (§8.12.19)';

    public function handle(Bindings $bindings, OrganisationContext $context): int
    {
        $targets = $context->acrossAllOrganisations(fn (): array => $this->targets());

        if ($targets === []) {
            $this->line('no bindings to probe');

            return self::SUCCESS;
        }

        $results = [];
        $failed = 0;

        foreach ($targets as $target) {
            /*
             * 🛑 Inside the tenancy span, because `Bindings::probe()` reads the
             * row and a driver may read configuration — and an
             * installation-scoped binding has a NULL `organisation_id` that
             * §8.2.1's scope would filter away.
             */
            $result = $context->acrossAllOrganisations(
                static fn () => $bindings->probe($target['id']),
            );

            $before = $target['state'];

            $after = $context->acrossAllOrganisations(
                static fn () => DB::table('auth_provider_bindings')
                    ->where('id', $target['id'])
                    ->value('state'),
            );

            $results[] = [
                'id' => Uuid::toText($target['id']),
                'name' => $target['name'],
                'type' => $target['type'],
                'passed' => $result->passed,
                'summary' => $result->summary,
                'state_before' => $before,
                'state_after' => is_string($after) ? $after : $before,
            ];

            if (! $result->passed) {
                $failed++;
            }
        }

        if ($this->option('json')) {
            $this->line((string) json_encode(['probes' => $results], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        } else {
            $this->newLine();

            foreach ($results as $row) {
                $icon = $row['passed'] ? '<fg=green>  ok  </>' : '<fg=red> FAIL </>';

                $this->line($icon.' '.str_pad($row['name'], 24).' <fg=gray>'.$row['type'].'</>');
                $this->line('        <fg=gray>'.$row['summary'].'</>');

                if ($row['state_before'] !== $row['state_after']) {
                    /*
                     * 🛑 Said out loud, because a probe that silently moved a
                     * binding to `degraded` is a probe that took a project
                     * offline and told nobody.
                     */
                    $this->line(
                        '        <fg=yellow>state '.$row['state_before'].' → '.$row['state_after'].'</>'
                    );
                }
            }

            $this->newLine();
            $this->line(sprintf('  %d probed, %d failed', count($results), $failed));
            $this->newLine();
        }

        if (! $this->option('check')) {
            return self::SUCCESS;
        }

        return $failed === 0 ? self::SUCCESS : self::FAILURE;
    }

    /**
     * The bindings to probe.
     *
     * 🛑 `draft` is **skipped** when probing everything, and included when one
     * is named. A draft binding is half-configured by definition, so probing
     * every draft on a schedule would fill the log with failures an operator
     * has not finished causing — but an operator probing a specific draft is
     * asking "is this right yet", which is the question the command is for.
     *
     * @return list<array{id: string, name: string, type: string, state: string}>
     */
    private function targets(): array
    {
        $named = $this->argument('binding');

        $query = DB::table('auth_provider_bindings')->orderBy('name');

        if (is_string($named) && $named !== '') {
            $id = Uuid::tryToBytes($named);

            $query->where(function ($q) use ($named, $id): void {
                $q->where('name', $named);

                if ($id !== null) {
                    $q->orWhere('id', $id);
                }
            });
        } else {
            $query->whereNotIn('state', [
                BindingState::Draft->value,
                BindingState::Disabled->value,
            ]);
        }

        $out = [];

        foreach ($query->get(['id', 'name', 'type', 'state']) as $row) {
            if (! is_string($row->id)) {
                continue;
            }

            $out[] = [
                'id' => $row->id,
                'name' => (string) $row->name,
                'type' => (string) $row->type,
                'state' => (string) $row->state,
            ];
        }

        return $out;
    }
}
