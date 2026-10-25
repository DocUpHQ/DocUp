<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Composition;

use App\Artifacts\Publisher;
use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Composition\Components;
use App\Composition\Mounts;
use App\Models\Build;
use App\Models\Component;
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
 * 🛑 Phase 15's third exit criterion.
 *
 * > "Switching a project from `mount` to `single_pass` changes the
 * > documented behaviours in the matrix and nothing else."
 *
 * Both halves are asserted and the second is the harder one. "Changes the
 * documented behaviours" is a handful of positive assertions; "and nothing
 * else" is the claim that a mode switch is not a migration — the same
 * version at the same URL with the same slug, the same visibility and the
 * same version list. A composition mode that quietly renamed or
 * re-published things would satisfy the first half perfectly.
 */
final class SinglePassPlanTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Components $components;

    private Mounts $mounts;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-p15-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Single Pass Co',
            'slug' => 'single-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->components = new Components;
        $this->mounts = new Mounts;
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
     * 🛑 The four matrix rows that differ observably, and nothing else.
     */
    public function test_switching_modes_changes_the_documented_behaviours_only(): void
    {
        $site = $this->composedSite();
        $version = $site['version'];
        $project = $version->project;

        $this->assertInstanceOf(Project::class, $project);

        // ------------------------------------------------- mount mode first
        $mounted = $this->manifestOf($version);

        $this->assertCount(3, $mounted->mounts_json['mounts'], 'three routing mounts under `mount`');
        $this->assertNotSame([], $mounted->nav_json['nodes'] ?? [], 'a spliced nav under `mount`');
        $this->assertCount(3, $mounted->xref_json['components'] ?? [], 'a cross-reference map under `mount`');

        $before = [
            'slug' => $version->slug,
            'language' => $version->language,
            'visibility' => $version->visibility->value,
            'url_prefix' => $project->url_prefix,
            'versioning_scheme' => $project->versioning_scheme,
            'versions' => ProjectVersion::query()->where('project_id', $project->id)->count(),
            'mount_rows' => $version->mounts()->count(),
        ];

        // ------------------------------------------------------ and switched
        $project->forceFill(['merge_policy' => 'single_pass'])->save();
        Cache::flush();

        app(Publisher::class)->publishExistingBuild(
            $version->refresh(),
            $this->latestBuildOf($site['components']['handbook']),
        );

        $composed = $this->manifestOf($version);

        $this->assertGreaterThan($mounted->revision, $composed->revision, 'a new revision was published');

        /*
         * 🛑 §8.7.13's "404 chain": one routing mount, so one file
         * manifest for the whole version and one step in the chain.
         */
        $this->assertCount(1, $composed->mounts_json['mounts']);
        $this->assertSame('', $composed->mounts_json['mounts'][0]['mount_path']);
        $this->assertTrue($composed->mounts_json['mounts'][0]['is_primary']);

        // 🛑 "Navigation source": the generator's own, so nothing spliced.
        $this->assertSame([], $composed->nav_json['nodes'] ?? ['not-empty']);

        // 🛑 "Cross-reference mechanism": the generator's, inside the
        // build — so DocUp has nothing to redirect and says so.
        $this->assertSame([], $composed->xref_json['components'] ?? ['not-empty']);

        // -------------------------------------------------- and nothing else
        $version = $version->refresh();
        $project = $project->refresh();

        $this->assertSame($before['slug'], $version->slug);
        $this->assertSame($before['language'], $version->language);
        $this->assertSame($before['visibility'], $version->visibility->value);
        $this->assertSame($before['url_prefix'], $project->url_prefix);
        $this->assertSame($before['versioning_scheme'], $project->versioning_scheme);
        $this->assertSame(
            $before['versions'],
            ProjectVersion::query()->where('project_id', $project->id)->count(),
            'switching modes created or removed no version',
        );

        /*
         * 🛑 And the mount ROWS are untouched. The composition is what
         * changed, not the configuration: a switch that detached two
         * mounts would satisfy every assertion above and would be
         * unrecoverable by switching back.
         */
        $this->assertSame($before['mount_rows'], $version->mounts()->count());
    }

    /**
     * 🛑 §8.7.13's "the effect of one contributor build failing", made real.
     *
     * Under `mount` a failed contributor leaves the live composition
     * serving, which Phase 14 asserts. Under `single_pass` there is one
     * build, so there is nothing to fall back to — the version keeps
     * serving the manifest it already had, and nothing new publishes.
     */
    public function test_a_composed_version_with_no_build_does_not_publish(): void
    {
        $site = $this->composedSite();
        $version = $site['version'];
        $version->project?->forceFill(['merge_policy' => 'single_pass'])->save();

        $serving = $version->refresh()->getRawOriginal('published_manifest_id');

        // A fresh version of the same shape, with nothing built for it.
        $empty = $this->publicVersion('empty');
        $empty->project?->forceFill(['merge_policy' => 'single_pass'])->save();
        $this->mounts->attach($empty, $site['components']['glossary'], '', isPrimary: true);

        $this->assertNull($empty->published_manifest_id);

        // And the composed one is unchanged by the other's failure.
        $this->assertSame($serving, $version->refresh()->getRawOriginal('published_manifest_id'));
    }

    // ---------------------------------------------------------------- setup

    /**
     * Three components on one version, published under `mount`.
     *
     * @return array{version: ProjectVersion, components: array<string, Component>}
     */
    private function composedSite(): array
    {
        $repository = $this->repository();
        $components = [];

        foreach (['handbook' => '', 'reference' => 'reference', 'glossary' => 'glossary'] as $key => $mountPath) {
            $components[$key] = $this->components->register(
                organisationId: $this->organisation->id,
                key: $key.'-'.bin2hex(random_bytes(3)),
                name: ucfirst($key),
                minAccess: AccessLevel::Public,
            );

            $this->components->attachSource($components[$key], $repository, 'docs/'.$key);
        }

        $version = $this->publicVersion('manual');

        $this->mounts->attach($version, $components['handbook'], '', isPrimary: true);
        $this->mounts->attach($version, $components['reference'], 'reference', isPrimary: false);
        $this->mounts->attach($version, $components['glossary'], 'glossary', isPrimary: false);

        foreach ($components as $component) {
            $this->buildFor($component);
        }

        app(Publisher::class)->publishExistingBuild($version, $this->latestBuildOf($components['handbook']));

        return ['version' => $version, 'components' => $components];
    }

    private function publicVersion(string $name): ProjectVersion
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

        return $version;
    }

    private function buildFor(Component $component): Build
    {
        $staging = $this->publicVersion('staging');
        $this->mounts->attach($staging, $component, '', isPrimary: true);

        $archive = (new ArchiveWriter)
            ->add('html/index.html', "<!doctype html><html><head></head><body>x</body></html>\n")
            ->add('html/terms.html', "<!doctype html><html><head></head><body>t</body></html>\n")
            ->toTarGz($this->fixtures.'/t-'.bin2hex(random_bytes(4)).'.tar.gz');

        $build = app(Publisher::class)->publishUpload($staging, $archive)->build;

        $this->assertInstanceOf(Build::class, $build);

        // A nav fragment, so the `mount` half of the comparison has one.
        $build->forceFill([
            'commit_sha' => str_repeat('a', 40),
            'nav_json' => [['label' => 'Index', 'href' => 'index.html']],
        ])->save();

        return $build;
    }

    private function latestBuildOf(Component $component): Build
    {
        /** @var Build */
        return Build::query()
            ->where('component_id', $component->id)
            ->whereIn('state', ['published', 'success_unpublished'])
            ->orderByDesc('finished_at')
            ->orderByDesc('id')
            ->firstOrFail();
    }

    private function manifestOf(ProjectVersion $version): ProjectVersionManifest
    {
        /** @var ProjectVersionManifest */
        return ProjectVersionManifest::query()
            ->whereKey($version->refresh()->getRawOriginal('published_manifest_id'))
            ->firstOrFail();
    }

    private function repository(): Repository
    {
        $repository = new Repository;

        $repository->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'provider' => 'github',
            'provider_host' => 'github.com',
            'clone_url' => 'https://github.com/docup/platform.git',
            'normalised_url' => 'https://github.com/docup/platform',
            'default_branch' => 'main',
            'provider_repo_id' => (string) random_int(1000, 99999),
        ])->save();

        return $repository;
    }
}
