<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Auth\Capability;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Versions\VersionOrder;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * §8.6's version list, as API v3 returns it.
 *
 * 🛑 **`listed` decides what is in this list and nothing else does.**
 * §8.6.2: "`hidden` is not `private`: a hidden version serves by direct URL
 * but is absent from the flyout, sitemap, `llms.txt` and search." This
 * endpoint is the first of those four surfaces to exist, and Phase 10's exit
 * criterion is literally about it — "A version with `listed=false` still
 * returns 200 by direct URL and is absent from the version list the API
 * returns".
 *
 * 🛑 **Ordered by {@see VersionOrder}, never by the database.** §8.6.5 makes
 * the flyout's order the project's comparator, and an API that returned
 * insertion order would be a second ordering for a client to disagree with
 * the flyout about. One order, one comparator, two readers.
 *
 * `?include=hidden` is for the dashboard, which must show the versions it
 * hid — they are hidden from readers, not from the people who hid them. It
 * needs `ProjectUpdate` rather than `ProjectView`, because the set of
 * hidden versions is itself information about the project.
 */
final class ProjectVersionController
{
    public function __construct(private readonly VersionOrder $order) {}

    /**
     * @param  string  $organisationSlug  bound by POSITION; see
     *                                    {@see ProjectController::show()} for
     *                                    why it is declared and unused.
     */
    public function index(Request $request, string $organisationSlug, Project $project): JsonResponse
    {
        abort_unless($request->user()?->can(Capability::ProjectView->value, $project) === true, 404);

        /** @var list<ProjectVersion> $versions */
        $versions = array_values(
            ProjectVersion::query()->where('project_id', $project->id)->get()->all(),
        );

        /*
         * `?include=hidden` is for the dashboard, and it needs more than
         * `ProjectView`: the SET of hidden versions is itself information
         * about the project, and a reader who may view it has not been
         * given that. `ProjectUpdate` is the capability somebody editing a
         * project's versions already holds.
         */
        // `->` rather than `?->`: the `abort_unless` above already
        // established there is a user, and a nullsafe call here would say
        // otherwise to anybody reading it.
        $includeHidden = $request->query('include') === 'hidden'
            && $request->user()->can(Capability::ProjectUpdate->value, $project) === true;

        $ordered = $includeHidden
            ? $this->order->forDashboard($project, $versions)
            : $this->order->forFlyout($project, $versions);

        return new JsonResponse([
            'data' => array_map(fn (ProjectVersion $version): array => $this->present($version), $ordered),
            'meta' => [
                'comparator' => (string) $project->version_comparator,
                'pin_channels_to_top' => (bool) $project->pin_channels_to_top,

                /*
                 * The two channels, as slugs rather than ids: a client
                 * rendering a flyout marks the entries, and matching on a
                 * slug it already has avoids a second lookup. Null is a real
                 * value — §8.6.4's step 5 makes "no `stable` at all" valid.
                 */
                'stable' => $this->slugOf($versions, $project->resolved_stable_version_id),
                'latest' => $this->slugOf($versions, $project->resolved_latest_version_id),
                'default' => $this->slugOf($versions, $project->default_version_id),
            ],
        ]);
    }

    /**
     * 🛑 The four axes are reported **separately**, not collapsed into a
     * status.
     *
     * §8.6.2 forbids deriving one from another, and an API that returned
     * `"status": "published"` would be exactly that derivation, performed
     * where every client would then depend on it. A client that wants one
     * word can compute it; a client that needs to know a version is active
     * and unlisted and public and unpublished can only learn it here.
     *
     * @return array<string, mixed>
     */
    private function present(ProjectVersion $version): array
    {
        return [
            'uuid' => $version->uuid,
            'slug' => $version->slug,
            'kind' => $version->kind,
            'language' => $version->language,

            'active' => $version->active,
            'listed' => $version->listed,
            'published' => $version->published,
            'visibility' => $version->visibility->value,

            'ref' => $version->ref_name === null ? null : [
                'name' => $version->ref_name,
                'kind' => $version->ref_kind,
                'commit_sha' => $version->ref_commit_sha,

                /*
                 * §8.6.15: a disappeared ref is reported rather than hidden.
                 * The version still serves by direct URL, and an operator
                 * looking at a list of versions should be able to see which
                 * of them no longer exist upstream without reading an audit
                 * log.
                 */
                'disappeared_at' => $version->ref_disappeared_at?->toJSON(),
            ],

            'wiped_at' => $version->wiped_at?->toJSON(),
        ];
    }

    /**
     * @param  list<ProjectVersion>  $versions
     */
    private function slugOf(array $versions, ?string $versionId): ?string
    {
        if ($versionId === null || $versionId === '') {
            return null;
        }

        foreach ($versions as $version) {
            if ($version->id === $versionId) {
                return $version->slug;
            }
        }

        return null;
    }
}
