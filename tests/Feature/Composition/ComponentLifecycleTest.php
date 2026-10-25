<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Composition;

use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Automation\AutomationEngine;
use App\Builds\Jobs\RunBuild;
use App\Builds\RepositoryFanout;
use App\Composition\Components;
use App\Composition\Mounts;
use App\Composition\SourceDirtiness;
use App\Models\BuildRequest;
use App\Models\Component;
use App\Models\ComponentMount;
use App\Models\ComponentSource;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\Repository;
use App\Support\Uuid;
use App\Versions\RefKind;
use App\Versions\RefSync;
use App\Versions\VersionOperations;
use App\Webhooks\PushEvent;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

/**
 * 🛑 Phase 13's two remaining exit criteria.
 *
 * > "One push triggers exactly the matching projects, asserted on enqueued
 * > jobs."
 *
 * > "Moving a component to a different repository changes one
 * > `component_sources` row and **no consuming project's mounts**."
 */
final class ComponentLifecycleTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Repository $monorepo;

    private Components $components;

    private Mounts $mounts;

    protected function setUp(): void
    {
        parent::setUp();

        Queue::fake();
        Storage::fake('artifacts');

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Lifecycle Co',
            'slug' => 'life-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->monorepo = $this->repository('https://github.com/docup/platform.git', '31337');
        $this->components = new Components;
        $this->mounts = new Mounts;
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    /**
     * 🛑 "One push triggers exactly the matching projects, asserted on
     * enqueued jobs."
     *
     * Three components at three subtrees of one monorepo, three projects,
     * one each. A push touching only `docs/api/**` must enqueue exactly
     * one job — and the assertion is on the **enqueued job list**, because
     * a project that builds and then discards the result satisfies "did
     * not change" while failing the thing that makes a monorepo
     * affordable.
     */
    public function test_one_push_triggers_exactly_the_matching_projects(): void
    {
        $projects = $this->threeProjectsFromOneMonorepo();

        $outcome = $this->fanout()->dispatch(
            $this->monorepo,
            $this->push(['docs/api/reference.md']),
        );

        $this->assertCount(1, $outcome->enqueued, 'exactly one project built');

        Queue::assertPushed(RunBuild::class, 1);

        $built = $outcome->enqueued[0]->project_version_id;

        $this->assertSame($projects['api']->id, $built, 'and it is the one whose subtree changed');

        // 🛑 And the other two left nothing in the queue — not a skipped
        // request, not a request at all. Their components were never dirty,
        // so the fan-out never reached them.
        $this->assertSame(
            1,
            BuildRequest::query()->where('organisation_id', $this->organisation->id)->count(),
            'a component whose subtree did not change produces no request',
        );
    }

    /** A push touching two subtrees triggers exactly those two. */
    public function test_a_push_across_two_subtrees_triggers_both(): void
    {
        $this->threeProjectsFromOneMonorepo();

        $outcome = $this->fanout()->dispatch(
            $this->monorepo,
            $this->push(['docs/api/reference.md', 'docs/guides/intro.md']),
        );

        $this->assertCount(2, $outcome->enqueued);
        Queue::assertPushed(RunBuild::class, 2);
    }

    /** A push touching nothing any component owns triggers nothing. */
    public function test_a_push_outside_every_subtree_triggers_nothing(): void
    {
        $this->threeProjectsFromOneMonorepo();

        $outcome = $this->fanout()->dispatch(
            $this->monorepo,
            $this->push(['src/main.go', 'README.md']),
        );

        $this->assertSame([], $outcome->enqueued);
        Queue::assertNothingPushed();
    }

    /**
     * 🛑 §8.5.4 and §18.15: a truncated payload rebuilds everything.
     *
     * §18.15's pre-decided consequence if path filtering turns out
     * untrustworthy is "default to rebuilding every component in a
     * repository on push", and {@see SourceDirtiness} is written so that is
     * what happens whenever the evidence is incomplete. A monorepo whose
     * pushes exceed the provider's file ceiling must not silently stop
     * rebuilding.
     */
    public function test_a_truncated_push_rebuilds_every_component(): void
    {
        $this->threeProjectsFromOneMonorepo();

        $outcome = $this->fanout()->dispatch(
            $this->monorepo,
            $this->push(['docs/api/reference.md'], truncated: true),
        );

        $this->assertCount(3, $outcome->enqueued, '§8.5.4: treat the payload as "everything changed"');
    }

    /** And so does a poll, which carries no file list at all. */
    public function test_a_source_with_no_push_is_always_dirty(): void
    {
        $source = new ComponentSource;
        $source->forceFill(['source_path' => 'docs/api', 'path_filters' => null]);

        $this->assertTrue((new SourceDirtiness)->isDirty($source, null));
    }

    /** An explicit `path_filters` list overrides the derived one. */
    public function test_explicit_path_filters_win_over_the_derived_one(): void
    {
        $dirtiness = new SourceDirtiness;

        $source = new ComponentSource;
        $source->forceFill([
            'source_path' => 'docs/api',
            'path_filters' => ['docs/api/**', 'shared/schema.json'],
        ]);

        $this->assertSame(['docs/api/**', 'shared/schema.json'], $dirtiness->globsFor($source));

        $this->assertTrue($dirtiness->isDirty($source, $this->push(['shared/schema.json'])));
        $this->assertFalse($dirtiness->isDirty($source, $this->push(['docs/guides/x.md'])));
    }

    /**
     * 🛑 A source at the repository ROOT narrows nothing, so every push
     * touches it.
     *
     * The single-component repository, which is most of them. Returning
     * "clean" here would mean an ordinary project silently never
     * rebuilding — the worst available failure for a default.
     */
    public function test_a_source_at_the_repository_root_is_always_dirty(): void
    {
        $source = new ComponentSource;
        $source->forceFill(['source_path' => '', 'path_filters' => null]);

        $this->assertSame([], (new SourceDirtiness)->globsFor($source));
        $this->assertTrue((new SourceDirtiness)->isDirty($source, $this->push(['anything.md'])));
    }

    /**
     * 🛑 "Moving a component to a different repository changes one
     * `component_sources` row and **no consuming project's mounts**."
     *
     * §8.7.1 calls this "the one lifecycle case that cannot be fixed later
     * without touching every consumer", which is why the assertion is on
     * the mounts being **byte-identical** afterwards rather than merely
     * still present.
     */
    public function test_moving_a_component_to_another_repository_touches_no_mount(): void
    {
        $component = $this->components->register(
            organisationId: $this->organisation->id,
            key: 'shared-'.bin2hex(random_bytes(3)),
            name: 'Shared',
            minAccess: AccessLevel::Public,
        );

        $source = $this->components->attachSource($component, $this->monorepo, 'docs/shared');

        // Three consumers, so "no consuming project's mounts" is plural.
        $versions = [];

        foreach (['one', 'two', 'three'] as $name) {
            $versions[$name] = $this->versionMounting($component, $name);
        }

        $before = $this->mountFingerprints($component);

        $this->assertCount(3, $before);

        // ------------------------------------------------- the move

        $extracted = $this->repository('https://github.com/docup/shared.git', '44444');

        $this->components->moveSource($source, $extracted, 'docs');

        // 🛑 ONE row changed.
        $source->refresh();

        $this->assertSame($extracted->id, $source->repository_id);
        $this->assertSame('docs', $source->source_path);

        $this->assertSame(
            1,
            ComponentSource::query()->where('component_id', $component->id)->count(),
            'the move changes the existing row; it does not add one',
        );

        // 🛑 And NO mount did.
        $this->assertSame(
            $before,
            $this->mountFingerprints($component),
            '🛑 §8.7.1: moving a repository must require no change to any consuming mount',
        );

        // The consumers still resolve to the same component, which is the
        // point of the component being the identity.
        foreach ($versions as $name => $version) {
            $this->assertSame(
                $component->id,
                ComponentMount::query()->where('project_version_id', $version->id)->sole()->component_id,
                $name.' lost its component',
            );
        }
    }

    /**
     * And the moved component now fans out from its NEW repository — which
     * is what makes the move a move rather than a detachment.
     */
    public function test_a_moved_component_is_triggered_by_its_new_repository(): void
    {
        $component = $this->components->register(
            organisationId: $this->organisation->id,
            key: 'shared-'.bin2hex(random_bytes(3)),
            name: 'Shared',
            minAccess: AccessLevel::Public,
        );

        $source = $this->components->attachSource($component, $this->monorepo, 'docs/shared');
        $this->versionMounting($component, 'consumer');

        $extracted = $this->repository('https://github.com/docup/shared.git', '55555');
        $this->components->moveSource($source, $extracted, '');

        // The old repository no longer reaches it.
        $this->assertSame(
            [],
            $this->fanout()->consumingProjects($this->monorepo),
            'the old repository must stop triggering the component it no longer holds',
        );

        // The new one does.
        $this->assertCount(1, $this->fanout()->consumingProjects($extracted));
    }

    // ---------------------------------------------------------------- helpers

    /**
     * Three components at three subtrees, each mounted by its own project.
     *
     * @return array<string, ProjectVersion>
     */
    private function threeProjectsFromOneMonorepo(): array
    {
        $versions = [];

        foreach (['api' => 'docs/api', 'guides' => 'docs/guides', 'shared' => 'docs/shared'] as $key => $path) {
            $component = $this->components->register(
                organisationId: $this->organisation->id,
                key: $key.'-'.bin2hex(random_bytes(3)),
                name: ucfirst($key),
                minAccess: AccessLevel::Public,
            );

            $this->components->attachSource($component, $this->monorepo, $path);

            $versions[$key] = $this->versionMounting($component, $key);
        }

        return $versions;
    }

    private function versionMounting(Component $component, string $name): ProjectVersion
    {
        $project = Project::query()->create([
            'slug' => $name.'-'.bin2hex(random_bytes(3)),
            'name' => ucfirst($name),
            'visibility' => 'public',
            'preview_policy' => 'all_dependent_versions',
        ]);

        $version = new ProjectVersion;
        $version->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $project->id,
            'slug' => 'main',
            'kind' => 'channel',
            'language' => 'en',
            'active' => true,
            'listed' => true,
            'published' => false,
            'visibility' => AccessLevel::Public->value,
            'ref_name' => 'main',
            'ref_kind' => 'branch',
            'ref_commit_sha' => str_repeat('0', 40),
        ])->save();

        $project->forceFill(['default_version_id' => $version->id])->save();

        $this->mounts->attach($version, $component);

        return $version;
    }

    /**
     * Every mount of a component, as comparable rows.
     *
     * 🛑 The whole row, not a count. "No consuming project's mounts
     * changed" is a claim about their contents — a move that silently
     * re-pointed a selector or re-snapshotted a ceiling would keep the
     * count and break the claim.
     *
     * @return list<array<string, mixed>>
     */
    private function mountFingerprints(Component $component): array
    {
        $rows = [];

        /** @var list<ComponentMount> $mounts */
        $mounts = array_values(
            ComponentMount::query()
                ->where('component_id', $component->id)
                ->orderBy('id')
                ->get()
                ->all(),
        );

        foreach ($mounts as $mount) {
            $rows[] = [
                'id' => bin2hex($mount->id),
                'project_version_id' => bin2hex($mount->project_version_id),
                'component_id' => bin2hex($mount->component_id),
                'mount_path' => $mount->mount_path,
                'base_url_mode' => $mount->base_url_mode,
                'is_primary' => $mount->is_primary,
                'is_required' => $mount->is_required,
                'min_access_snapshot' => $mount->min_access_snapshot->value,
                'updated_at' => $mount->updated_at?->toIso8601String(),
            ];
        }

        return $rows;
    }

    private function repository(string $cloneUrl, string $providerRepoId): Repository
    {
        $repository = new Repository;

        $repository->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'provider' => 'github',
            'provider_host' => 'github.com',
            'clone_url' => $cloneUrl,
            'normalised_url' => rtrim($cloneUrl, '.git'),
            'default_branch' => 'main',
            'provider_repo_id' => $providerRepoId,
        ])->save();

        return $repository;
    }

    private function fanout(): RepositoryFanout
    {
        return new RepositoryFanout(
            app(RefSync::class),
            new AutomationEngine(app(VersionOperations::class)),
        );
    }

    /** @param list<string> $paths */
    private function push(array $paths, bool $truncated = false): PushEvent
    {
        return new PushEvent(
            deliveryId: 'd-'.bin2hex(random_bytes(4)),
            event: 'push',
            repositoryIdentifier: null,
            refName: 'main',
            refKind: RefKind::Branch,
            commitSha: str_repeat('b', 40),
            changedPaths: $paths,
            commitMessages: ['docs: update'],
            payloadTruncated: $truncated,
        );
    }
}
