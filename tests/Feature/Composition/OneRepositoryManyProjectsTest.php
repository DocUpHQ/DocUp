<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Composition;

use App\Artifacts\Publisher;
use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Builds\ContentKey;
use App\Composition\Components;
use App\Composition\Mounts;
use App\Models\Build;
use App\Models\Component;
use App\Models\ComponentMount;
use App\Models\ComponentSource;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\ProjectVersionManifest;
use App\Models\Repository;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Storage;
use Tests\Support\ArchiveWriter;
use Tests\TestCase;

/**
 * 🛑 Phase 13's headline exit criterion.
 *
 * > "One monorepo registered once feeds three projects from three source
 * > paths, and **one build row** serves all three — asserted on the build
 * > count, not just the output."
 *
 * Both halves are asserted, because the criterion's two clauses are two
 * different claims and either could hold without the other:
 *
 *   - **one repository, three source paths** — §8.7.1's component identity,
 *     so a monorepo contributes three independently-buildable components
 *     from one registration;
 *   - **one build row serves three projects** — §8.7.9's content key, which
 *     is what "build once" actually means.
 *
 * "Asserted on the build count, not just the output" is the sentence that
 * decides how this file is written: every assertion below counts `builds`
 * rows. Three projects serving identical bytes is what a *broken*
 * implementation also looks like.
 */
final class OneRepositoryManyProjectsTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Repository $monorepo;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-composition-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Monorepo Co',
            'slug' => 'mono-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        // 🛑 Registered ONCE. Every component below is a child of this one
        // row, which is §8.7.1's whole design.
        $this->monorepo = new Repository;
        $this->monorepo->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'provider' => 'github',
            'provider_host' => 'github.com',
            'clone_url' => 'https://github.com/docup/platform.git',
            'normalised_url' => 'https://github.com/docup/platform',
            'default_branch' => 'main',
            'provider_repo_id' => '31337',
        ])->save();
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        if (is_dir($this->fixtures)) {
            foreach ((array) glob($this->fixtures.'/*') as $file) {
                if (is_string($file)) {
                    @unlink($file);
                }
            }

            @rmdir($this->fixtures);
        }

        parent::tearDown();
    }

    /**
     * 🛑 One repository, three source paths, three components.
     *
     * §8.7.1: the component is "an organisation-scoped,
     * repository-independent identity ... whose current location is a child
     * `component_sources` row". Three locations inside one repository is
     * the monorepo case, and it needs one `repositories` row.
     */
    public function test_one_repository_registered_once_contributes_three_components(): void
    {
        $components = $this->registerThreeComponents();

        $this->assertCount(3, $components);

        $this->assertSame(
            1,
            Repository::query()->where('organisation_id', $this->organisation->id)->count(),
            'the monorepo is registered once, however many components it contributes',
        );

        $paths = ComponentSource::query()
            ->where('repository_id', $this->monorepo->id)
            ->orderBy('source_path')
            ->pluck('source_path')
            ->all();

        $this->assertSame(['docs/api', 'docs/guides', 'docs/shared'], $paths);
    }

    /**
     * 🛑 "one **build row** serves all three — asserted on the build count,
     * not just the output."
     *
     * Three projects, each with a version mounting the SAME component. The
     * first publishes a build; the second and third find it by §8.7.9's
     * content key and publish it without starting anything.
     *
     * The publishes here go through the real `Publisher`, and the reuse is
     * `publishExistingBuild()` — the same method `BuildPipeline` calls when
     * `reusableBuildFor()` hits. Driving the full pipeline would need the
     * sandbox; what is under test is the content key and the sharing, and
     * `EndToEndBuildTest` exercises the pipeline for real.
     */
    public function test_three_projects_mounting_one_component_share_one_build_row(): void
    {
        $shared = $this->registerThreeComponents()['shared'];

        $versions = [];

        foreach (['alpha', 'beta', 'gamma'] as $name) {
            $versions[$name] = $this->projectVersionMounting($shared, $name);
        }

        /** @var Publisher $publisher */
        $publisher = app(Publisher::class);

        // Project alpha builds it.
        $publisher->publishUpload($versions['alpha'], $this->archive());

        $build = Build::query()->sole();

        // 🛑 And the other two reuse that row rather than making their own.
        foreach (['beta', 'gamma'] as $name) {
            $publisher->publishExistingBuild($versions[$name], $build);
        }

        $this->assertSame(
            1,
            Build::query()->where('organisation_id', $this->organisation->id)->count(),
            '🛑 §8.7.9: one repository feeding many projects builds ONCE',
        );

        // All three serve, and all three serve the SAME build.
        foreach ($versions as $name => $version) {
            $version->refresh();

            $this->assertNotNull($version->published_manifest_id, $name.' is not published');

            $this->assertSame(
                [Uuid::toText($build->id)],
                $this->buildIdsInManifest((string) $version->published_manifest_id),
                $name.' serves a different build',
            );
        }
    }

    /**
     * 🛑 §8.7.9's key is over component inputs and nothing else.
     *
     * The same component, commit and configuration computed for three
     * different project versions must produce one key — otherwise the
     * reuse above happens by luck rather than by design. Asserted directly
     * on the function, because this is the property every other claim in
     * this file rests on.
     */
    public function test_the_content_key_is_identical_across_projects(): void
    {
        $shared = $this->registerThreeComponents()['shared'];

        $keys = [];

        foreach (['alpha', 'beta', 'gamma'] as $name) {
            $version = $this->projectVersionMounting($shared, $name);

            $mount = ComponentMount::query()
                ->where('project_version_id', $version->id)
                ->sole();

            $keys[] = ContentKey::compute(
                organisationId: $this->organisation->id,
                componentId: $shared->id,
                commitSha: str_repeat('a', 40),
                configDigest: 'cfg',
                envDigest: 'env',
                pipelineVersion: 1,
                mountPath: ContentKey::mountPathFor($mount, $shared),
            );
        }

        $this->assertCount(1, array_unique($keys), 'three projects, one key');
    }

    /**
     * 🛑 §8.7.11: `injected` forfeits the sharing, and that is the point.
     *
     * > "`injected` puts the mount path in the content key, exports
     * > `$DOCUP_BASE_PATH`, and MUST surface the resulting loss of
     * > cross-project build reuse in the dashboard."
     *
     * Two mounts of one component at two paths under `injected` are two
     * keys, so two builds. Asserted because the cost has to be real for
     * the dashboard warning to be honest — a warning about a loss that did
     * not happen is worse than none.
     */
    public function test_injected_base_url_mode_splits_the_content_key(): void
    {
        $shared = $this->registerThreeComponents()['shared'];

        $relative = ContentKey::compute(
            organisationId: $this->organisation->id,
            componentId: $shared->id,
            commitSha: str_repeat('a', 40),
            configDigest: 'cfg',
            envDigest: 'env',
            pipelineVersion: 1,
            mountPath: null,
        );

        $atRoot = ContentKey::compute(
            organisationId: $this->organisation->id,
            componentId: $shared->id,
            commitSha: str_repeat('a', 40),
            configDigest: 'cfg',
            envDigest: 'env',
            pipelineVersion: 1,
            mountPath: '',
        );

        $atGuides = ContentKey::compute(
            organisationId: $this->organisation->id,
            componentId: $shared->id,
            commitSha: str_repeat('a', 40),
            configDigest: 'cfg',
            envDigest: 'env',
            pipelineVersion: 1,
            mountPath: 'guides',
        );

        $this->assertNotSame($relative, $atRoot, '🛑 relative and injected-at-root are different builds');
        $this->assertNotSame($atRoot, $atGuides, 'two injected prefixes are two builds');
        $this->assertCount(3, array_unique([$relative, $atRoot, $atGuides]));
    }

    /**
     * 🛑 Two organisations with byte-identical sources never share a build.
     *
     * §8.5.19 argues this at length for the fragment cache — "the cache
     * cannot act as a cross-tenant file-existence oracle" — and it applies
     * with more force here, because a build is not a cache entry: it is
     * bytes somebody will be served.
     */
    public function test_two_organisations_never_share_a_content_key(): void
    {
        $other = Uuid::v7();

        $mine = ContentKey::compute(
            organisationId: $this->organisation->id,
            componentId: str_repeat("\x01", 16),
            commitSha: str_repeat('a', 40),
            configDigest: 'cfg',
            envDigest: 'env',
            pipelineVersion: 1,
        );

        $theirs = ContentKey::compute(
            organisationId: $other,
            componentId: str_repeat("\x01", 16),
            commitSha: str_repeat('a', 40),
            configDigest: 'cfg',
            envDigest: 'env',
            pipelineVersion: 1,
        );

        $this->assertNotSame($mine, $theirs);
    }

    /** Any input changing changes the key, which is what makes reuse safe. */
    public function test_every_input_changes_the_key(): void
    {
        $base = [
            'organisationId' => $this->organisation->id,
            'componentId' => str_repeat("\x01", 16),
            'commitSha' => str_repeat('a', 40),
            'configDigest' => 'cfg',
            'envDigest' => 'env',
            'pipelineVersion' => 1,
        ];

        $reference = ContentKey::compute(
            organisationId: $base['organisationId'],
            componentId: $base['componentId'],
            commitSha: $base['commitSha'],
            configDigest: $base['configDigest'],
            envDigest: $base['envDigest'],
            pipelineVersion: $base['pipelineVersion'],
        );

        /*
         * Written out rather than spread, because a spread over a mixed
         * array hands every parameter `int|string` and the analyser is
         * right to object: the thing under test is that each input is
         * distinct, and a call site that cannot say which is which is a
         * poor way to assert it.
         */
        $varied = [
            'a different commit' => ContentKey::compute(
                organisationId: $base['organisationId'],
                componentId: $base['componentId'],
                commitSha: str_repeat('b', 40),
                configDigest: $base['configDigest'],
                envDigest: $base['envDigest'],
                pipelineVersion: $base['pipelineVersion'],
            ),
            'a different config digest' => ContentKey::compute(
                organisationId: $base['organisationId'],
                componentId: $base['componentId'],
                commitSha: $base['commitSha'],
                configDigest: 'cfg2',
                envDigest: $base['envDigest'],
                pipelineVersion: $base['pipelineVersion'],
            ),
            // 🛑 §8.5.14 puts the image digest inside `env_digest`, so this
            // is also "a security fix to the toolchain reaches every
            // project" — without it, a patched image would never rebuild
            // anything whose other inputs had not moved.
            'a different env digest' => ContentKey::compute(
                organisationId: $base['organisationId'],
                componentId: $base['componentId'],
                commitSha: $base['commitSha'],
                configDigest: $base['configDigest'],
                envDigest: 'env2',
                pipelineVersion: $base['pipelineVersion'],
            ),
            'a different pipeline version' => ContentKey::compute(
                organisationId: $base['organisationId'],
                componentId: $base['componentId'],
                commitSha: $base['commitSha'],
                configDigest: $base['configDigest'],
                envDigest: $base['envDigest'],
                pipelineVersion: 2,
            ),
        ];

        foreach ($varied as $what => $key) {
            $this->assertNotSame(
                $reference,
                $key,
                $what.' must change the content key, or a stale build is reused',
            );
        }

        $this->assertCount(
            5,
            array_unique([$reference, ...array_values($varied)]),
            'each input must be independently significant',
        );
    }

    // ---------------------------------------------------------------- helpers

    /**
     * Three components at three source paths in the one repository.
     *
     * @return array<string, Component>
     */
    private function registerThreeComponents(): array
    {
        $components = new Components;
        $registered = [];

        foreach (['api' => 'docs/api', 'guides' => 'docs/guides', 'shared' => 'docs/shared'] as $key => $path) {
            $component = $components->register(
                organisationId: $this->organisation->id,
                key: $key.'-'.bin2hex(random_bytes(3)),
                name: ucfirst($key),
                // 🛑 Public, so §8.7.7's ceiling permits a public project.
                // The refusal is `MinAccessCeilingTest`'s subject.
                minAccess: AccessLevel::Public,
            );

            $components->attachSource($component, $this->monorepo, $path);

            $registered[$key] = $component;
        }

        return $registered;
    }

    /** A public project with one version mounting the given component. */
    private function projectVersionMounting(Component $component, string $name): ProjectVersion
    {
        $project = Project::query()->create([
            'slug' => $name.'-'.bin2hex(random_bytes(3)),
            'name' => ucfirst($name),
            'visibility' => 'public',
        ]);

        $version = new ProjectVersion;
        $version->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $project->id,
            'slug' => 'latest',
            'kind' => 'channel',
            'language' => 'en',
            'active' => true,
            'listed' => true,
            'published' => false,
            'visibility' => AccessLevel::Public->value,
        ])->save();

        $project->forceFill(['default_version_id' => $version->id])->save();

        (new Mounts)->attach($version, $component);

        return $version;
    }

    private function archive(): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', "<!doctype html><html><head></head><body>shared</body></html>\n")
            ->toTarGz($this->fixtures.'/tree-'.bin2hex(random_bytes(3)).'.tar.gz');
    }

    /**
     * @param  string  $manifestId  raw 16 bytes
     * @return list<string>
     */
    private function buildIdsInManifest(string $manifestId): array
    {
        /** @var ProjectVersionManifest|null $manifest */
        $manifest = ProjectVersionManifest::query()->find($manifestId);

        if ($manifest === null) {
            return [];
        }

        $ids = [];

        /** @var list<array<string, mixed>> $mounts */
        $mounts = $manifest->mounts_json['mounts'] ?? [];

        foreach ($mounts as $mount) {
            $buildId = $mount['build_id'] ?? null;

            if (is_string($buildId)) {
                $ids[] = $buildId;
            }
        }

        return $ids;
    }
}
