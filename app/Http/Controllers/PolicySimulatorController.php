<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Access\AccessSurface;
use App\Access\PolicySimulator;
use App\Access\ReaderGate;
use App\Access\SimulatedIdentity;
use App\Access\SimulationAnswer;
use App\Access\SimulationRefused;
use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\Capability;
use App\Auth\RoleResolver;
use App\Http\Middleware\ResolveOrganisation;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ReaderIdentity;
use App\Models\User;
use App\Support\Uuid;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Inertia\Inertia;
use Inertia\Response;

/**
 * 🛑 §8.12.25's "MUST exist **in the UI**", which is the part of the
 * requirement that is easy to satisfy on paper and easy to miss in practice.
 *
 * A simulator reachable only from a console command is a simulator the person
 * who writes the policy does not use, and §19/40's failure mode — "operators
 * default projects to public" — is about the person clicking through a
 * dashboard, not the one with a shell.
 *
 * ## 🛑 A GET, and the answer is linkable
 *
 * The simulation is a read: it mints nothing, writes nothing and changes
 * nothing (see {@see ReaderGate::simulate()}), so a POST would be
 * a lie about what it does and would make the answer unlinkable. An operator
 * who finds a surprising result wants to paste it to a colleague, and that
 * colleague has to see the same answer — the same identity, the same URL, the
 * same surface. Query parameters are what make that true.
 *
 * Nothing sensitive travels in them: a project's own documentation URL and the
 * **id** of an identity, never a credential and never an email (§8.12.1 does
 * not permit one to exist on a reader identity in the first place).
 *
 * ## 🛑 Why this audits and the simulator does not
 *
 * The simulator is also the linter's and the test suite's engine, so auditing
 * inside it would put a hundred rows and a hundred chain locks behind a test
 * run. Here there is exactly one actor and exactly one question, which is what
 * an audit row is for. §8.22.4 asks for an event per state-changing action and
 * this changes nothing — it is recorded because the *question* is sensitive:
 * "who can read this" is the question somebody asks before they exfiltrate, and
 * §20.3's trail is the only place that would show it was asked.
 */
final class PolicySimulatorController
{
    /**
     * @param  string  $organisationSlug  the `{organisation}` route parameter,
     *                                    already resolved and authorised by
     *                                    {@see ResolveOrganisation}.
     *                                    Declared because route parameters bind
     *                                    by POSITION — see
     *                                    {@see ProjectController::show()} for
     *                                    what omitting it does.
     */
    public function __invoke(
        Request $request,
        string $organisationSlug,
        Project $project,
        PolicySimulator $simulator,
    ): Response {
        /** @var Organisation $organisation */
        $organisation = $request->attributes->get('organisation');

        abort_unless(
            $request->user()?->can(Capability::ProjectPolicySimulate->value, $project) === true,
            404,
        );

        /** @var User $actor */
        $actor = $request->user();

        $validated = $request->validate([
            /*
             * 🛑 Both nullable: the page must render before anything has been
             * asked. A simulator that demanded inputs to show its own form
             * would be a simulator an operator meets as a validation error.
             */
            'host' => ['nullable', 'string', 'max:253'],
            'path' => ['nullable', 'string', 'max:2048'],
            'identity' => ['nullable', 'string', 'in:anonymous,reader,member'],
            'subject' => ['nullable', 'string', 'uuid'],
            'address' => ['nullable', 'ip'],
            'surface' => ['nullable', 'string', 'in:proxy,download,search,addons'],
        ]);

        $answer = null;
        $refused = null;

        $host = isset($validated['host']) && is_string($validated['host']) ? $validated['host'] : null;

        if ($host !== null && $host !== '') {
            try {
                $answer = $simulator->simulate(
                    identity: $this->identity($validated),
                    host: $host,
                    path: $this->path($validated),
                    surface: AccessSurface::tryFrom(
                        is_string($validated['surface'] ?? null) ? $validated['surface'] : 'proxy',
                    ) ?? AccessSurface::Proxy,
                );

                Audit::record(
                    action: 'policy.simulated',
                    actorType: ActorType::User,
                    organisationId: $organisation->id,
                    actorId: $actor->id,
                    subjectType: 'project',
                    subjectId: $project->id,
                    reasonCode: $answer->decision?->reason->value,
                    ruleId: $answer->decision?->rule?->id,
                    payload: [
                        /*
                         * 🛑 §8.22.5: identifiers, codes and references only.
                         * The summary is {@see AccessDecision::header()}'s fixed
                         * vocabulary; the host and path are the operator's own
                         * project's, which the audit row already names.
                         */
                        'summary' => $answer->summary(),
                        'identity_kind' => $answer->identity->kind->value,
                        'surface' => $validated['surface'] ?? 'proxy',
                    ],
                );
            } catch (SimulationRefused $exception) {
                $refused = $exception->reasonCode;
            }
        }

        return Inertia::render('Projects/PolicySimulator', [
            'organisation' => ['slug' => $organisation->slug, 'name' => $organisation->name],
            'project' => [
                'uuid' => $project->uuid,
                'slug' => $project->slug,
                'name' => $project->name,
                'visibility' => $project->visibility->value,
            ],
            'hosts' => $this->hosts($project),
            'identities' => $this->identities($project),
            'members' => $this->members(),
            'asked' => [
                'host' => $host,
                'path' => $this->path($validated),
                'identity' => $validated['identity'] ?? 'anonymous',
                'subject' => $validated['subject'] ?? null,
                'address' => $validated['address'] ?? null,
                'surface' => $validated['surface'] ?? 'proxy',
            ],
            'refused' => $refused,
            'answer' => $answer === null ? null : $this->present($answer),
        ]);
    }

    /**
     * The identity the operator chose, with the stored id decoded.
     *
     * 🛑 Anonymous whenever the subject is missing, rather than an error. The
     * form's first state has no subject and the most important simulation an
     * operator can run is the anonymous one — §19/40's failure mode is a
     * project that is public without anybody meaning it.
     *
     * @param  array<string, mixed>  $validated
     */
    private function identity(array $validated): SimulatedIdentity
    {
        $address = is_string($validated['address'] ?? null) ? $validated['address'] : null;
        $subject = is_string($validated['subject'] ?? null) ? Uuid::tryToBytes($validated['subject']) : null;

        if ($subject === null) {
            return SimulatedIdentity::anonymous($address);
        }

        return match ($validated['identity'] ?? 'anonymous') {
            'reader' => SimulatedIdentity::reader($subject, $address),
            'member' => SimulatedIdentity::member($subject, $address),
            default => SimulatedIdentity::anonymous($address),
        };
    }

    /** @param  array<string, mixed>  $validated */
    private function path(array $validated): string
    {
        $path = $validated['path'] ?? '/';

        return is_string($path) && $path !== '' ? $path : '/';
    }

    /**
     * The hosts this project is actually served on, so the operator picks
     * rather than types.
     *
     * 🛑 §8.9.3 resolves a project from the host and the path, so a typo in the
     * host does not produce a wrong answer — it produces an answer about
     * another project, or about nothing. Offering the real list is what stops
     * the most likely operator error from looking like a policy bug.
     *
     * @return list<array{host: string, state: string}>
     */
    private function hosts(Project $project): array
    {
        /** @var list<object{host: string, state: string}> $rows */
        $rows = DB::table('domain_mounts')
            ->join('domains', 'domains.id', '=', 'domain_mounts.domain_id')
            ->where('domain_mounts.project_id', $project->id)
            ->distinct()
            ->select('domains.host', 'domains.state')
            ->orderBy('domains.host')
            ->get()
            ->all();

        return array_map(
            static fn (object $row): array => ['host' => $row->host, 'state' => $row->state],
            $rows,
        );
    }

    /**
     * The organisation's reader identities, by label.
     *
     * 🛑 Scoped by §8.2.1's global scope, and deliberately **not** filtered to
     * this project: §8.12.3 scopes a binding at installation, organisation or
     * project level, so an identity vouched for by an organisation-scope
     * binding is a legitimate reader of every project under it. Filtering by
     * project would hide exactly the identities an operator is most surprised
     * by.
     *
     * Deprovisioned rows are excluded, because {@see PolicySimulator} refuses
     * them — offering a choice the tool then rejects is a worse interface than
     * not offering it.
     *
     * @return list<array{uuid: string, label: string, groups: list<string>}>
     */
    private function identities(Project $project): array
    {
        /*
         * `array_values` because an Eloquent collection's `all()` is an
         * `array<int, …>` rather than a provable list — see the return type.
         */
        return array_values(ReaderIdentity::query()
            ->whereNull('deprovisioned_at')
            ->orderBy('display_label')
            ->limit(200)
            ->get()
            ->map(fn (ReaderIdentity $identity): array => [
                /*
                 * 🛑 Cast rather than `?? ''`. {@see HasUuidKey} types `uuid` as
                 * nullable because a model with no key yet has none; a row that
                 * came back from a query always does, and a silent empty string
                 * would be an identity the simulator then refuses as unknown.
                 */
                'uuid' => (string) $identity->uuid,
                'label' => $identity->display_label ?? 'unnamed reader',
                'groups' => $this->groups($identity),
            ])
            ->all());
    }

    /**
     * @return list<string>
     */
    private function groups(ReaderIdentity $identity): array
    {
        $decoded = json_decode((string) ($identity->reader_groups ?? '[]'), true);

        if (! is_array($decoded)) {
            return [];
        }

        return array_values(array_filter($decoded, 'is_string'));
    }

    /**
     * The organisation's dashboard members, for §12.3's `members` rung.
     *
     * 🛑 Drawn from `role_assignments` on this organisation rather than from
     * `users`, which is installation-wide: offering every account on the
     * installation would list other organisations' people in this tenant's
     * dashboard. {@see RoleResolver} still decides what each one
     * reaches, including an installation-scope role this query cannot see — so
     * the list is who to *offer*, never who is authorised.
     *
     * @return list<array{uuid: string, label: string}>
     */
    private function members(): array
    {
        /** @var list<string> $ids */
        $ids = DB::table('role_assignments')
            ->where('subject_type', 'user')
            ->whereNotNull('organisation_id')
            ->distinct()
            ->pluck('subject_id')
            ->all();

        if ($ids === []) {
            return [];
        }

        return array_values(User::query()
            ->whereIn('id', $ids)
            ->orderBy('name')
            ->limit(200)
            ->get()
            ->map(static fn (User $user): array => [
                'uuid' => (string) $user->uuid,
                'label' => $user->name,
            ])
            ->all());
    }

    /**
     * §8.12.25's sentence, as the page's props.
     *
     * 🛑 `rule` carries the **position**, which is what §8.12.25 asks for
     * ("by rule 7") and what §8.12.6's first-match-wins makes meaningful. The
     * label comes with it because a position alone is a number an operator has
     * to go and look up.
     *
     * @return array<string, mixed>
     */
    private function present(SimulationAnswer $answer): array
    {
        $decision = $answer->decision;

        return [
            'summary' => $answer->summary(),
            'resolved' => $answer->reachedAVersion(),
            'route_rule' => $answer->routeRule,
            'rejection' => $answer->rejection,
            'redirect_to' => $answer->redirectTo,
            'project_slug' => $answer->projectSlug,
            'version_slug' => $answer->versionSlug,
            'language' => $answer->language,
            'mount_relative_path' => $answer->mountRelativePath,
            'identity_label' => $answer->identityLabel,
            'identity_groups' => $answer->identityGroups,
            'unsimulatable' => array_map(
                static fn ($leaf): string => $leaf->value,
                $answer->unsimulatable,
            ),
            'decision' => $decision === null ? null : [
                'allowed' => $decision->allowed,
                'status' => $decision->status,
                'reason' => $decision->reason->value,
                'required' => $decision->required->value,
                'established' => $decision->established->value,
                'challenge' => $decision->mayChallenge(),
                'publicly_cacheable' => $decision->rulePubliclyCacheable,
                'satisfied_by' => $decision->satisfiedBy?->value,
                'satisfied_by_binding' => $answer->satisfiedByBinding,
                'rule' => $decision->rule === null ? null : [
                    'position' => $decision->rule->position,
                    'label' => $decision->rule->label,
                    'allow' => $decision->rule->allow,
                ],
                /*
                 * 🛑 The shadow rule is shown because §8.12.22's linter is
                 * about reachability changes and this is the one place an
                 * operator can see one coming: a shadow rule that would have
                 * matched is the next edit's behaviour, visible before the
                 * edit.
                 */
                'shadow_rule' => $decision->shadowRule === null ? null : [
                    'position' => $decision->shadowRule->position,
                    'label' => $decision->shadowRule->label,
                    'allow' => $decision->shadowRule->allow,
                ],
            ],
        ];
    }
}
