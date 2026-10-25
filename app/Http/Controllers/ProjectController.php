<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Auth\Capability;
use App\Composition\CompositionSummary;
use App\Http\Middleware\ResolveOrganisation;
use App\Models\Organisation;
use App\Models\Project;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

/**
 * The dashboard surface for projects.
 *
 * 🛑 §8.2.2: cross-tenant access returns **404, never 403**, and here that
 * needs no code at all. Route binding resolves `{project}` through the §8.2.1
 * global scope, so a project in another organisation is simply not found and
 * the framework renders 404. A 403 would require code that first located the
 * row — and locating it is already the leak.
 *
 * The capability check below is therefore about what a *member* may do, not
 * about tenancy. The two are different questions and this is the only place
 * they meet.
 */
final class ProjectController
{
    public function index(Request $request): Response
    {
        /** @var Organisation $organisation */
        $organisation = $request->attributes->get('organisation');

        // Scoped by §8.2.1, so this cannot return another tenant's projects
        // even if someone forgets a where clause — which is the point of the
        // scope being global rather than a trait method people remember.
        $projects = Project::query()->orderBy('slug')->get();

        return Inertia::render('Projects/Index', [
            'organisation' => ['slug' => $organisation->slug, 'name' => $organisation->name],
            'projects' => $projects->map(fn (Project $project): array => [
                'uuid' => $project->uuid,
                'slug' => $project->slug,
                'name' => $project->name,
                'visibility' => $project->visibility->value,
            ])->all(),
        ]);
    }

    /**
     * @param  string  $organisationSlug  the `{organisation}` route parameter.
     *                                    Unused — {@see ResolveOrganisation}
     *                                    has already resolved and authorised it — but
     *                                    declared because route parameters bind by
     *                                    POSITION. Omitting it made Laravel pass the
     *                                    slug as $project, which failed with a
     *                                    TypeError rather than anything that reads
     *                                    like a routing mistake.
     */
    public function show(Request $request, string $organisationSlug, Project $project): Response
    {
        // Membership got the request this far; this decides what they may see
        // of it. §12.1: the gate is the only call site.
        // `=== true`, not a nullable bool: abort_unless() treats null as
        // falsy and would 404 anyway, but relying on that makes the
        // security of this line depend on a coercion rule nobody checks.
        abort_unless($request->user()?->can(Capability::ProjectView->value, $project) === true, 404);

        return Inertia::render('Projects/Show', [
            'project' => [
                'uuid' => $project->uuid,
                'slug' => $project->slug,
                'name' => $project->name,
                'description' => $project->description,
                'visibility' => $project->visibility->value,
                'inherits_organisation_roles' => $project->inherit_organisation_roles,
            ],

            /*
             * 🛑 §8.7.11's dashboard warning: "`injected` ... MUST surface
             * the resulting loss of cross-project build reuse in the
             * dashboard."
             *
             * Carried as data with the warning already decided, so the
             * template renders a string rather than reimplementing the
             * rule — a `v-if="mode === 'injected'"` in a `.vue` file is a
             * second place that knows what `injected` costs, and the two
             * would eventually disagree.
             */
            'composition' => (new CompositionSummary)->forProject($project),
        ]);
    }
}
