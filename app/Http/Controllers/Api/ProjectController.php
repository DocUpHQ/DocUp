<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Auth\Capability;
use App\Http\Middleware\ResolveOrganisation;
use App\Models\Project;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * The API surface for projects.
 *
 * 🛑 §8.2.2 names the UI, the API **and direct identifier access** as three
 * routes that must all answer 404. This is the second and third: `{project}`
 * binds by UUID as well as by slug, so asking for a known identifier from
 * another organisation resolves nothing and 404s — knowing the key does not
 * help, which is the whole point of the requirement listing identifier access
 * separately.
 */
final class ProjectController
{
    public function index(Request $request): JsonResponse
    {
        $projects = Project::query()->orderBy('slug')->get();

        return new JsonResponse([
            'data' => $projects->map(fn (Project $project): array => $this->present($project))->all(),
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
    public function show(Request $request, string $organisationSlug, Project $project): JsonResponse
    {
        // `=== true`, not a nullable bool: abort_unless() treats null as
        // falsy and would 404 anyway, but relying on that makes the
        // security of this line depend on a coercion rule nobody checks.
        abort_unless($request->user()?->can(Capability::ProjectView->value, $project) === true, 404);

        return new JsonResponse(['data' => $this->present($project)]);
    }

    /**
     * 🛑 The internal key is never exposed. `uuid` is the canonical text form
     * from ADR 0006's presentation boundary; the raw 16 bytes stay inside the
     * application, where they are the only thing that queries correctly.
     *
     * @return array<string, mixed>
     */
    private function present(Project $project): array
    {
        return [
            'uuid' => $project->uuid,
            'slug' => $project->slug,
            'name' => $project->name,
            'description' => $project->description,
            'visibility' => $project->visibility->value,
        ];
    }
}
