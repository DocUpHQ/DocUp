<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Access\ReaderPolicies;
use App\Auth\OrganisationContext;
use App\Auth\Providers\BindingState;
use App\Auth\Providers\DriverRegistry;
use App\Support\Uuid;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

/**
 * `docup:auth:list` — §17's operator view of every binding.
 *
 * 🛑 **This is the installation's only window onto its own authorisation
 * configuration**, because no dashboard surface exists for it yet — five
 * phases have now not built one. So the command does more than list: it
 * carries the two warnings §8.12.19 asks a UI to carry, because the
 * alternative is that nothing carries them.
 *
 * > "A degraded binding MUST deny with a branded 503 … A zero-rule policy MUST
 * > deny with a red banner."
 *
 * 🛑 **No secret is printed**, ever, and not even a redacted shape of one.
 * §8.12.2: "envelope-encrypted secrets no API or UI ever returns" — a CLI is a
 * UI, and `docup:auth:list | tee` is how a secret reaches a file nobody
 * remembers writing.
 */
final class AuthListCommand extends Command
{
    protected $signature = 'docup:auth:list
        {--project= : Only bindings in scope for this project slug}
        {--json : Machine-readable output}
        {--check : Exit non-zero if any binding is degraded or any policy has no rules}';

    protected $description = 'List every authentication binding, its state and its warnings (§8.12.2)';

    public function handle(OrganisationContext $context, ReaderPolicies $policies): int
    {
        /*
         * 🛑 Across every organisation. An installation operator running this
         * is asking about the installation, and an installation-scoped binding
         * has a NULL `organisation_id` that §8.2.1's global scope would filter
         * away — the same reason `RoleResolver` queries directly.
         */
        $rows = $context->acrossAllOrganisations(fn (): array => $this->rows());

        $warnings = $this->warnings($context, $policies);

        if ($this->option('json')) {
            $this->line((string) json_encode([
                'bindings' => $rows,
                'warnings' => $warnings,
                'registered_drivers' => DriverRegistry::types(),
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        } else {
            $this->render($rows, $warnings);
        }

        if (! $this->option('check')) {
            return self::SUCCESS;
        }

        return $warnings === [] ? self::SUCCESS : self::FAILURE;
    }

    /** @return list<array<string, mixed>> */
    private function rows(): array
    {
        $slug = $this->option('project');

        $query = DB::table('auth_provider_bindings')
            ->leftJoin('projects', 'projects.id', '=', 'auth_provider_bindings.scope_id')
            ->orderBy('auth_provider_bindings.scope_type')
            ->orderBy('auth_provider_bindings.name');

        if (is_string($slug) && $slug !== '') {
            /*
             * 🛑 "In scope for" is not "scoped to": §8.12.3 resolves
             * installation and organisation bindings down onto a project, so a
             * filter that showed only project-scoped rows would hide the
             * binding actually guarding it — which is the one the operator is
             * looking for.
             */
            $project = DB::table('projects')->where('slug', $slug)->first(['id', 'organisation_id']);

            if ($project === null) {
                $this->warn('no project with slug "'.$slug.'"');

                return [];
            }

            $query->where(function ($q) use ($project): void {
                $q->where('auth_provider_bindings.scope_type', 'installation')
                    ->orWhere(function ($inner) use ($project): void {
                        $inner->where('auth_provider_bindings.scope_type', 'organisation')
                            ->where('auth_provider_bindings.scope_id', $project->organisation_id);
                    })
                    ->orWhere(function ($inner) use ($project): void {
                        $inner->where('auth_provider_bindings.scope_type', 'project')
                            ->where('auth_provider_bindings.scope_id', $project->id);
                    });
            });
        }

        $out = [];

        foreach ($query->get([
            'auth_provider_bindings.id',
            'auth_provider_bindings.scope_type',
            'auth_provider_bindings.scope_id',
            'auth_provider_bindings.type',
            'auth_provider_bindings.name',
            'auth_provider_bindings.state',
            'auth_provider_bindings.shareable',
            'auth_provider_bindings.probe',
            'auth_provider_bindings.probe_failures',
            'auth_provider_bindings.verified_at',
            'projects.slug as project_slug',
        ]) as $row) {
            $probe = is_string($row->probe) ? json_decode((string) $row->probe, true, 8) : null;

            $out[] = [
                'id' => is_string($row->id) ? Uuid::toText($row->id) : null,
                'scope' => (string) $row->scope_type,
                'target' => is_string($row->project_slug) ? $row->project_slug : '—',
                'type' => (string) $row->type,
                'name' => (string) $row->name,
                'state' => (string) $row->state,
                'shareable' => (bool) $row->shareable,
                /* 🛑 Whether a driver is still installed for this stored type. */
                'driver_installed' => DriverRegistry::for((string) $row->type) !== null,
                'probe' => is_array($probe) ? ($probe['passed'] ?? null) : null,
                'probe_summary' => is_array($probe) && is_string($probe['summary'] ?? null)
                    ? $probe['summary']
                    : null,
                'probe_failures' => is_numeric($row->probe_failures) ? (int) $row->probe_failures : 0,
                'test_login' => $row->verified_at !== null,
            ];
        }

        return $out;
    }

    /**
     * 🛑 §8.12.19's two warnings, which no UI currently carries.
     *
     * @return list<array{kind: string, detail: string, ref: string}>
     */
    private function warnings(OrganisationContext $context, ReaderPolicies $policies): array
    {
        return $context->acrossAllOrganisations(function () use ($policies): array {
            $warnings = [];

            /* 🛑 A degraded binding is denying readers right now. */
            $degraded = DB::table('auth_provider_bindings')
                ->where('state', BindingState::Degraded->value)
                ->get(['name', 'type']);

            foreach ($degraded as $binding) {
                $warnings[] = [
                    'kind' => 'binding_degraded',
                    'detail' => 'binding "'.$binding->name.'" ('.$binding->type.') is DEGRADED and is '
                        .'answering readers with a 503; it will not fall back to public',
                    'ref' => 'SPEC 8.12.19',
                ];
            }

            /* 🛑 A stored type with no installed driver, which degrades too. */
            $types = DB::table('auth_provider_bindings')->distinct()->pluck('type');

            foreach ($types as $type) {
                if (is_string($type) && DriverRegistry::for($type) === null) {
                    $warnings[] = [
                        'kind' => 'driver_missing',
                        'detail' => 'bindings of type "'.$type.'" exist and no driver is registered; '
                            .'they answer readers with a 503',
                        'ref' => 'SPEC 8.12.2',
                    ];
                }
            }

            /*
             * 🛑 §8.12.19's red banner, as the only place it currently exists:
             * "A zero-rule policy MUST deny with a red banner."
             *
             * The **denial** is already enforced — §10.6 makes
             * `reader_policies.default_effect` a single-valued `ENUM('deny')`,
             * so a policy with no rules denies everything by construction. What
             * was missing is anybody being told, and a dashboard banner cannot
             * be built before a dashboard. This is the honest substitute, and
             * it is recorded in the build log as owed to the UI phase.
             *
             * 🛑 Asked of {@see ReaderPolicies} rather than queried here.
             * That class is the sole reader of the policy tables, and the
             * architecture suite enforces it — because first-match-wins has
             * exactly one reading and a second query is a second reading. The
             * invariant caught this command when it was written the other way.
             */
            foreach ($policies->projectsWithNoRules() as $slug) {
                $warnings[] = [
                    'kind' => 'policy_has_no_rules',
                    'detail' => 'project "'.$slug.'" has a reader policy with NO RULES, '
                        .'so every reader is denied; add a rule or delete the policy',
                    'ref' => 'SPEC 8.12.19',
                ];
            }

            return $warnings;
        });
    }

    /**
     * @param  list<array<string, mixed>>  $rows
     * @param  list<array{kind: string, detail: string, ref: string}>  $warnings
     */
    private function render(array $rows, array $warnings): void
    {
        $this->newLine();

        if ($rows === []) {
            $this->line('  No authentication bindings are configured.');
            $this->line('  <fg=gray>Every project is governed by §12.3\'s lattice alone: a public project');
            $this->line('  serves, and a private one admits only its own members (§8.12.10).</>');
        } else {
            $this->table(
                ['scope', 'target', 'type', 'name', 'state', 'probe', 'test login'],
                array_map(static fn (array $row): array => [
                    $row['scope'],
                    $row['target'],
                    $row['type'].($row['driver_installed'] ? '' : ' <fg=red>(no driver)</>'),
                    $row['name'],
                    match ($row['state']) {
                        'active' => '<fg=green>active</>',
                        'degraded' => '<fg=red>DEGRADED</>',
                        'verifying' => '<fg=yellow>verifying</>',
                        default => '<fg=gray>'.$row['state'].'</>',
                    },
                    match ($row['probe']) {
                        true => '<fg=green>pass</>',
                        false => '<fg=red>fail ('.$row['probe_failures'].')</>',
                        default => '<fg=gray>never run</>',
                    },
                    $row['test_login'] ? '<fg=green>yes</>' : '<fg=gray>no</>',
                ], $rows),
            );
        }

        if ($warnings === []) {
            $this->newLine();

            return;
        }

        $this->newLine();

        foreach ($warnings as $warning) {
            $this->line('  <fg=red>⚠  '.$warning['detail'].'</>');
            $this->line('     <fg=gray>'.$warning['ref'].'</>');
        }

        $this->newLine();
    }
}
