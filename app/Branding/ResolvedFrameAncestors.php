<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

use App\Auth\OrganisationContext;
use App\Models\Project;
use App\Serving\SnapshotProject;
use App\Support\Uuid;
use App\Versions\ChannelResolver;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 §8.14.16's `frame-ancestors`, resolved and written where the serving path
 * can read it.
 *
 * > §8.14.16: "Documentation `frame-ancestors` MUST be a per-project token
 * > defaulting to `'self'`, with an explicit origin allowlist and never `*`."
 *
 * Phase 27 built and validated the token and said plainly that nothing emitted
 * it: "A security setting an operator can change and that does nothing is worse
 * than one that is absent, because they would believe their documentation was
 * protected." The token's own `purpose` text — printed in the operator
 * documentation — said "Stored and validated; not yet enforced". Phase 28
 * enforces it, because this is the phase that puts chrome in the DOM and
 * therefore the phase with something to protect from being framed.
 *
 * ## 🛑 Why the value is denormalised onto the project
 *
 * §8.14.15's documentation CSP goes on **every document response**. Resolving
 * the §8.14.1 cascade there is not available: §8.9.1 requires the resolver to
 * run "with no database queries" from a pre-loaded snapshot, and §9.2's budget
 * has no room for a four-rung theme resolution per request. So the resolved
 * value is written when the inputs change and read as a column, which
 * {@see SnapshotProject} carries like any other routing fact.
 *
 * That is the pattern `projects.resolved_stable_version_id` and
 * `resolved_latest_version_id` already use in the same table — a value derived
 * by a stated rule, written when the inputs change, read on the hot path — and
 * {@see ChannelResolver} is its `reconcile()`.
 *
 * ## 🛑 The fan-out is bounded by the token's own cascade depth
 *
 * `security.frame-ancestors` is declared `deepest: CascadeLevel::Project`, so a
 * mount or version revision **cannot** set it and needs no reconciliation at
 * all. What remains:
 *
 * - a project revision reconciles one project;
 * - an organisation revision reconciles that organisation's projects;
 * - an installation revision reconciles every project on the installation.
 *
 * The last is O(projects) and is an operator action taken rarely — an
 * installation-scope theme publish — so it runs in the publish rather than in a
 * queue. Said out loud because it is the one case that scales with the
 * installation: a thousand-project installation pays a thousand cascade
 * resolutions on that one publish, and the alternative was a four-rung
 * resolution on every document request forever.
 */
final readonly class ResolvedFrameAncestors
{
    /** The token this class exists for. */
    public const string TOKEN = 'security.frame-ancestors';

    /** §8.14.16's default, and the value a never-reconciled project reads as. */
    public const string DEFAULT = "'self'";

    public function __construct(private OrganisationContext $context) {}

    /**
     * Reconcile every project a published revision at this scope can affect.
     *
     * @param  string|null  $scopeId  the revision's scope id, raw bytes or text;
     *                                null for installation scope
     * @return int how many projects were written
     */
    public function reconcile(CascadeLevel $level, ?string $scopeId): int
    {
        /*
         * 🛑 Asked of the registry rather than hard-coded here. If a later
         * release gives the token mount depth, this stops being correct and the
         * registry is the only place that would say so — so it is the place
         * that is asked.
         */
        $token = TokenRegistry::all()[self::TOKEN] ?? null;

        if ($token === null || ! $token->settableAt($level)) {
            return 0;
        }

        return $this->context->acrossAllOrganisations(function () use ($level, $scopeId): int {
            $query = Project::withoutGlobalScopes()->whereNull('deleted_at');

            if ($level === CascadeLevel::Organisation && $scopeId !== null) {
                $query->where('organisation_id', Uuid::tryToBytes($scopeId) ?? str_repeat("\xff", 16));
            }

            if ($level === CascadeLevel::Project && $scopeId !== null) {
                $query->whereKey(Uuid::tryToBytes($scopeId) ?? str_repeat("\xff", 16));
            }

            $written = 0;

            /*
             * Chunked, because the installation-scope case is every project on
             * the installation and loading them all would put the fan-out's
             * cost in memory as well as in time.
             */
            $query->chunkById(200, function (iterable $projects) use (&$written): void {
                foreach ($projects as $project) {
                    if ($this->write($project)) {
                        $written++;
                    }
                }
            });

            return $written;
        });
    }

    /**
     * Resolve and store one project's value.
     *
     * @return bool whether the stored value changed
     */
    public function write(Project $project): bool
    {
        $resolved = $this->resolve($project);

        if ($project->resolved_frame_ancestors === $resolved) {
            return false;
        }

        /*
         * 🛑 A direct update rather than `$project->save()`. This runs inside a
         * theme publish, and saving the model would fire its events and touch
         * `updated_at` — which on `projects` is a column an operator reads as
         * "when did somebody change this project". A derived value being
         * recomputed is not somebody changing the project, and the same argument
         * applies to `resolved_stable_version_id`.
         */
        DB::table('projects')
            ->where('id', $project->id)
            ->update(['resolved_frame_ancestors' => $resolved]);

        $project->resolved_frame_ancestors = $resolved;

        return true;
    }

    /**
     * The value this project's cascade resolves the token to.
     *
     * 🛑 Through the one {@see Themes} resolution, never a bespoke query. The
     * whole point of §8.14.1's cascade being one left fold is that a second
     * reader of the same rungs cannot disagree with it — and this value ends up
     * in a security header, where disagreeing with the theme an operator can
     * see in the dashboard would be the worst possible place to be subtly
     * wrong.
     */
    public function resolve(Project $project): string
    {
        $theme = Themes::make((string) $project->organisation_id, (string) $project->id)
            ->resolve(new ThemeTarget(
                organisationId: (string) $project->organisation_id,
                projectId: (string) $project->id,
            ));

        $value = $theme->serialised(self::TOKEN);

        return $value === null || $value === '' ? self::DEFAULT : $value;
    }
}
