<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

use App\Models\Component;
use App\Models\ComponentMount;
use App\Models\ComponentSource;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Support\Uuid;

/**
 * What a project's composition looks like, for the dashboard.
 *
 * 🛑 §8.7.11 asks for one specific thing and it is the reason this class
 * exists: "`injected` puts the mount path in the content key, exports
 * `$DOCUP_BASE_PATH`, and **MUST surface the resulting loss of
 * cross-project build reuse in the dashboard**."
 *
 * A cost that is real and invisible is a cost nobody weighs. `injected` is
 * the right answer for a generator that bakes absolute URLs, and choosing
 * it means this component is rebuilt per mount for ever — which an
 * operator should find out when they choose it, not when their build
 * minutes triple.
 *
 * Read-only and shaped for a view. §8.7.21's `/_/composition` endpoint is
 * P14's and answers a different question — "what was on this URL on
 * 2026-03-04?" — from the published manifest rather than from the current
 * edges.
 */
final readonly class CompositionSummary
{
    /**
     * The mounts of every version of a project, newest version first.
     *
     * @return list<array<string, mixed>>
     */
    public function forProject(Project $project): array
    {
        /** @var list<ProjectVersion> $versions */
        $versions = array_values(
            ProjectVersion::query()
                ->where('project_id', $project->id)
                ->orderByDesc('id')
                ->get()
                ->all(),
        );

        $rows = [];

        foreach ($versions as $version) {
            /** @var list<ComponentMount> $mounts */
            $mounts = array_values(
                ComponentMount::query()
                    ->where('project_version_id', $version->id)
                    ->orderBy('mount_path')
                    ->get()
                    ->all(),
            );

            foreach ($mounts as $mount) {
                $component = $mount->component;

                if (! $component instanceof Component) {
                    continue;
                }

                $rows[] = $this->describe($version, $mount, $component);
            }
        }

        return $rows;
    }

    /** @return array<string, mixed> */
    private function describe(ProjectVersion $version, ComponentMount $mount, Component $component): array
    {
        $mode = $mount->base_url_mode ?? $component->default_base_url_mode;
        $source = ComponentSource::query()
            ->where('component_id', $component->id)
            ->where('state', 'active')
            ->first();

        return [
            'version' => $version->slug,
            'language' => $version->language,
            'component' => $component->key,
            'component_name' => $component->name,
            'mount_path' => $mount->mount_path,
            'is_primary' => $mount->is_primary,

            /*
             * 🛑 §8.7.7's ceiling, shown beside the mount. An operator
             * looking at a public project needs to see that one of its
             * components demands `members` — not because it can happen
             * (the mount would have been refused) but because loosening
             * the project later cannot happen either, and the reason
             * should be visible before they try.
             */
            'min_access' => $mount->min_access_snapshot->value,

            'base_url_mode' => $mode,

            /*
             * 🛑 The warning §8.7.11 requires, as a field rather than as
             * prose in a template. A view can style it; a test can assert
             * it; an API can return it. Prose in a `.vue` file is none of
             * those, and it is also where a warning goes to be deleted by
             * somebody tidying up a layout.
             */
            'shares_builds' => $mode !== 'injected',
            'reuse_warning' => $mode === 'injected'
                ? 'This mount uses base_url_mode: injected, so its mount path is part of the build'
                    .' identity (§8.7.9). This component is rebuilt separately for every project and'
                    .' every mount path that uses it, and cannot share a build with any of them.'
                : null,

            'repository' => $source instanceof ComponentSource
                ? Uuid::toText($source->repository_id)
                : null,
            'source_path' => $source?->source_path,
        ];
    }
}
