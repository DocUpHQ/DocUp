<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\AccessLevel;
use App\Auth\Capability;
use App\Models\Project;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;

/**
 * Changes a project's visibility — §8.2.10's kill switch.
 *
 * 🛑 A single-action controller, and not merely to satisfy the Pest `laravel`
 * preset's rule about controller methods. §8.2.10 makes this column the
 * operator's one switch for stopping all public access, §8.12.13 treats a
 * change to it as an access-stopping event, and §8.13.5 puts it in the
 * 5-minute step-up window. A class of its own means the middleware, the
 * capability check and the audit event sit together where a reviewer can see
 * all three at once — rather than being one method among several, each with
 * different requirements, in a controller whose route declarations live
 * elsewhere.
 */
final class ProjectVisibilityController
{
    /**
     * Change a project's visibility (§8.2.10, §8.13.5, §8.22.4).
     *
     * 🛑 Behind `stepup:project.visibility.update`, which §8.13.5 puts in the
     * 5-minute window. §8.2.10 calls this column the operator's single kill
     * switch and §8.12.13 treats a change to it as an access-stopping event —
     * so a stolen session an hour old must not be able to publish a private
     * project.
     */
    public function __invoke(Request $request, string $organisationSlug, Project $project): RedirectResponse
    {
        abort_unless(
            $request->user()?->can(Capability::ProjectVisibilityUpdate->value, $project) === true,
            404,
        );

        $validated = $request->validate([
            // Validated against the enum rather than a string list, so the
            // §12.3 lattice has one definition and this cannot drift from it.
            'visibility' => ['required', Rule::enum(AccessLevel::class)],
        ]);

        $was = $project->visibility;
        $now = AccessLevel::from((string) $validated['visibility']);

        if ($was !== $now) {
            DB::transaction(function () use ($project, $was, $now, $request): void {
                $project->visibility = $now;
                $project->save();

                // §8.22.4: the mutation and its audit row in one transaction.
                Audit::record(
                    action: 'project.visibility.changed',
                    actorType: ActorType::User,
                    organisationId: $project->organisation_id,
                    // Not nullsafe: the `auth` middleware guarantees a user
                    // here, and PHPStan knows it. A `?->` would imply this can
                    // be a system action, which it cannot.
                    actorId: $request->user()->id,
                    subjectType: 'project',
                    subjectId: $project->id,
                    payload: ['from' => $was->value, 'to' => $now->value],
                );
            });
        }

        return redirect()->route('organisations.projects.show', [
            'organisation' => $organisationSlug,
            'project' => $project->slug,
        ]);
    }
}
