<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Docs;

use App\Auth\AccessLevel;
use App\Composition\Components;
use App\Composition\Mounts;
use App\Models\Component;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\Repository;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * Stands DocUp's own manual up as a composed project (§17 Phase 17).
 *
 * Three repositories, three components, one project version, three mounts and
 * §8.7.6's layout tree — through the same `Components` and `Mounts` services
 * an operator's dashboard will use, never by writing the rows directly. That
 * is the whole value of dogfooding: a provisioner that bypassed the write
 * path would exercise the schema and prove nothing about the product.
 *
 * 🛑 **Idempotent**, because the first thing anybody does with a command like
 * this is run it twice. Re-running adopts what already exists rather than
 * refusing, so an operator who added a guide gets the new one attached and
 * keeps the published manifests of the other two.
 *
 * It does **not** trigger builds. §8.5 owns that, a webhook or
 * `docup:poll-repositories` starts it, and a provisioner that also built
 * would be the one place in the product where a configuration change
 * implicitly spent a sandbox.
 */
final readonly class DogfoodProvisioner
{
    public function __construct(
        private Components $components = new Components,
        private Mounts $mounts = new Mounts,
    ) {}

    /**
     * Provision the manual, returning the version it is served from.
     *
     * @param  string  $organisationId  raw 16 bytes
     * @param  array<string, string>  $repositories  guide key => clone URL, overriding the plan's defaults
     */
    public function provision(string $organisationId, array $repositories = []): ProjectVersion
    {
        return DB::transaction(function () use ($organisationId, $repositories): ProjectVersion {
            $project = $this->project($organisationId);
            $version = $this->version($project, $organisationId);

            foreach (DogfoodPlan::guides() as $guide) {
                $component = $this->component($organisationId, $guide);

                $this->source(
                    $component,
                    $this->repository($organisationId, $repositories[$guide['key']] ?? $guide['repository']),
                );

                $this->mount($version, $component, $guide['mount']);
            }

            /*
             * Written last, because §8.7.6's required includes name
             * components and an unresolvable required include fails the
             * publication. Writing the tree before the mounts exist would
             * leave a version that cannot publish between two statements of
             * one transaction — invisible here, and not invisible to a
             * publish that raced it.
             */
            $version->forceFill(['layout_json' => DogfoodPlan::layout()])->save();

            return $version;
        });
    }

    private function project(string $organisationId): Project
    {
        $project = Project::query()->where('slug', DogfoodPlan::PROJECT)->first();

        if ($project instanceof Project) {
            return $project;
        }

        return Project::query()->create([
            'slug' => DogfoodPlan::PROJECT,
            'name' => 'DocUp',
            'description' => "DocUp's own manual, composed from three repositories.",
            'visibility' => AccessLevel::Public->value,
        ]);
    }

    private function version(Project $project, string $organisationId): ProjectVersion
    {
        $version = ProjectVersion::query()
            ->where('project_id', $project->id)
            ->where('slug', 'latest')
            ->where('language', 'en')
            ->first();

        if (! $version instanceof ProjectVersion) {
            $version = new ProjectVersion;

            $version->forceFill([
                'id' => Uuid::v7(),
                'organisation_id' => $organisationId,
                'project_id' => $project->id,
                'slug' => 'latest',
                'kind' => 'channel',
                'language' => 'en',
                'ref_name' => 'main',
                'ref_kind' => 'branch',
                'active' => true,
                'listed' => true,
                'published' => false,
                'visibility' => AccessLevel::Public->value,
            ])->save();
        }

        if ($project->default_version_id === null) {
            $project->forceFill(['default_version_id' => $version->id])->save();
        }

        return $version;
    }

    /**
     * @param  array{key: string, name: string, mount: string, directory: string, repository: string, pages: list<string>}  $guide
     */
    private function component(string $organisationId, array $guide): Component
    {
        $existing = Component::query()->where('key', $guide['key'])->first();

        if ($existing instanceof Component) {
            return $existing;
        }

        /*
         * 🛑 `public`, stated rather than defaulted. §8.7.7 makes
         * `min_access` a ceiling owned by the source and `Components` defaults
         * it to `members` precisely so that publishing is a decision. This
         * manual is published documentation, so the decision is made here and
         * is visible in one line.
         */
        return $this->components->register(
            organisationId: $organisationId,
            key: $guide['key'],
            name: $guide['name'],
            minAccess: AccessLevel::Public,
        );
    }

    private function source(Component $component, Repository $repository): void
    {
        $already = DB::table('component_sources')
            ->where('component_id', $component->id)
            ->where('repository_id', $repository->id)
            ->exists();

        if ($already) {
            return;
        }

        // The repository root: each guide is its own repository, so there is
        // no subtree to narrow to. In this monorepo the directory in
        // DogfoodPlan is how the fallback build finds the same pages.
        $this->components->attachSource($component, $repository);
    }

    private function mount(ProjectVersion $version, Component $component, string $path): void
    {
        $already = $version->mounts()->where('component_id', $component->id)->exists();

        if ($already) {
            return;
        }

        $this->mounts->attach(
            version: $version,
            component: $component,
            mountPath: $path,
            isPrimary: $path === '',
        );
    }

    /**
     * A repository row for a clone URL, adopted when it already exists.
     *
     * Normalisation is the same shape §8.3.8 uses as a fallback matching key:
     * the URL without a trailing `.git`. A provisioner that invented its own
     * normalisation would create a second row for a repository the poller
     * already knows.
     */
    private function repository(string $organisationId, string $cloneUrl): Repository
    {
        $normalised = rtrim(preg_replace('/\.git$/', '', $cloneUrl) ?? $cloneUrl, '/');

        $existing = Repository::query()->where('normalised_url', $normalised)->first();

        if ($existing instanceof Repository) {
            return $existing;
        }

        $repository = new Repository;

        $repository->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $organisationId,
            'provider' => 'github',
            'provider_host' => (string) (parse_url($normalised, PHP_URL_HOST) ?: 'github.com'),
            'clone_url' => $normalised.'.git',
            'normalised_url' => $normalised,
            'default_branch' => 'main',
        ])->save();

        return $repository;
    }
}
