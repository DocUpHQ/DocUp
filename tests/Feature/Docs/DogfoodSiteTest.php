<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Docs;

use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
use App\Composition\Mounts;
use App\Docs\DogfoodPlan;
use App\Docs\DogfoodProvisioner;
use App\Models\Build;
use App\Models\Component;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\ProjectVersionManifest;
use App\Models\Repository;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Yaml\Yaml;
use Tests\Support\ArchiveWriter;
use Tests\TestCase;

/**
 * 🛑 Phase 17's first exit criterion.
 *
 * > "The project's own documentation site serves the operator guide, the
 * > author guide and the `.docup.yaml` reference from three repositories as
 * > one manual."
 *
 * Through the real provisioner and the real route table. The provisioner is
 * the point: a test that wrote the rows itself would prove the schema works
 * and nothing about whether an operator can stand this up, which is what
 * dogfooding is for.
 *
 * 🛑 The **pages are the real ones**. Each guide's artifact is built from the
 * Markdown committed in `docs/`, so a guide that loses a page loses it here
 * too — this is the test that stops the manual and the plan drifting apart.
 */
final class DogfoodSiteTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private string $host;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-p17-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'DocUp',
            'slug' => 'docup-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);
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
     * 🛑 Three repositories, one manual, served.
     */
    public function test_three_repositories_serve_as_one_manual(): void
    {
        $version = $this->provisionAndPublish();

        $this->getExactly("http://{$this->host}/en/latest/")
            ->assertOk();

        // Each guide answers under its own mount, from its own repository.
        $this->getExactly("http://{$this->host}/en/latest/installing.html")->assertOk();
        $this->getExactly("http://{$this->host}/en/latest/author/builds.html")->assertOk();
        $this->getExactly("http://{$this->host}/en/latest/reference/index.html")->assertOk();

        // 🛑 Three repositories, not one with three subtrees. §8.7.1 makes a
        // component repository-independent, so the thing worth asserting is
        // that three distinct repository rows produced this site.
        $this->assertSame(
            3,
            DB::table('build_sources')
                ->whereIn('build_id', $this->buildIdsOf($version))
                ->distinct()
                ->count('repository_id'),
        );
    }

    /**
     * 🛑 One navigation tree, arranged by topic rather than by repository.
     *
     * §8.7.6's two layers: the project writes the headings and splices each
     * component's fragment underneath. A reader sees "Running it" and
     * "Reference", never a repository name.
     */
    public function test_the_manual_has_one_navigation_tree_arranged_by_topic(): void
    {
        $version = $this->provisionAndPublish();

        $nav = $this->manifestOf($version)->nav_json;

        $this->assertIsArray($nav);
        $this->assertSame(
            ['Running it', 'Writing documentation', 'Reference'],
            array_map(
                static fn (array $node): string => (string) ($node['label'] ?? ''),
                $nav['nodes'] ?? [],
            ),
        );

        // And the hrefs underneath carry each guide's mount prefix, which is
        // what makes one tree out of three independent fragments.
        $hrefs = $this->hrefsIn($nav['nodes'] ?? []);

        $this->assertContains('installing.html', $hrefs, 'the operator guide is mounted at the root');
        $this->assertContains('author/builds.html', $hrefs, 'the author guide carries its prefix');
        $this->assertContains('reference/index.html', $hrefs, 'the reference carries its prefix');
    }

    /**
     * 🛑 §8.7.21: the manifest answers which commit of which repository
     * produced any URL.
     */
    public function test_the_composition_endpoint_names_all_three_repositories(): void
    {
        $this->provisionAndPublish();

        $response = $this->getExactly("http://{$this->host}/_/composition");
        $response->assertOk();

        /** @var array{versions: list<array{components: list<array<string, mixed>>}>} $payload */
        $payload = $response->json();

        $this->assertCount(1, $payload['versions']);

        $keys = array_map(
            static fn (array $component): string => (string) ($component['component'] ?? ''),
            $payload['versions'][0]['components'],
        );

        sort($keys);

        $this->assertSame(['docup-author', 'docup-operator', 'docup-reference'], $keys);
    }

    /**
     * 🛑 Running the provisioner twice changes nothing.
     *
     * The first thing anybody does with a command like this is run it again,
     * and an operator who has published the manual must not lose it to a
     * second `docup:dogfood`.
     */
    public function test_provisioning_twice_is_idempotent(): void
    {
        $provisioner = app(DogfoodProvisioner::class);

        $first = $provisioner->provision($this->organisation->id);
        $second = $provisioner->provision($this->organisation->id);

        $this->assertSame($first->id, $second->id);
        $this->assertSame(3, $second->mounts()->count());
        $this->assertSame(3, Component::query()->count());
        $this->assertSame(3, Repository::query()->count());
    }

    /**
     * Overriding one guide's repository attaches that repository, not a
     * fourth copy of the default.
     */
    public function test_a_repository_override_is_honoured(): void
    {
        app(DogfoodProvisioner::class)->provision($this->organisation->id, [
            'docup-author' => 'https://git.example.test/docup/author-guide.git',
        ]);

        $component = Component::query()->where('key', 'docup-author')->firstOrFail();

        $url = DB::table('component_sources')
            ->join('repositories', 'repositories.id', '=', 'component_sources.repository_id')
            ->where('component_sources.component_id', $component->id)
            ->value('repositories.normalised_url');

        $this->assertSame('https://git.example.test/docup/author-guide', $url);
    }

    // ---------------------------------------------------------------- setup

    /** Provision the manual and publish a real artifact per guide. */
    private function provisionAndPublish(): ProjectVersion
    {
        $version = app(DogfoodProvisioner::class)->provision($this->organisation->id);

        $project = $version->project;
        $this->assertNotNull($project);

        $this->host = $project->slug.'.'.$this->docsApex();
        $this->giveTheProjectADefaultSubdomain($project->id);

        foreach (DogfoodPlan::guides() as $guide) {
            $component = Component::query()->where('key', $guide['key'])->firstOrFail();

            $this->buildFor($component, $guide);
        }

        $primary = Component::query()->where('key', 'docup-operator')->firstOrFail();

        $outcome = app(Publisher::class)->publishExistingBuild($version->refresh(), $this->latestBuildOf($primary));

        $this->assertTrue($outcome->published, 'the manual published');

        Cache::flush();

        return $version->refresh();
    }

    /**
     * A build of one guide, from the Markdown actually committed in `docs/`.
     *
     * Not the rendered HTML — rendering is MkDocs' job and the sandbox tests
     * cover it. What this asserts is the composition: that the pages the plan
     * names exist, and that each guide's artifact carries exactly them.
     *
     * @param  array{key: string, name: string, mount: string, directory: string, repository: string, pages: list<string>}  $guide
     */
    private function buildFor(Component $component, array $guide): Build
    {
        $staging = $this->stagingVersionFor($component);

        $writer = new ArchiveWriter;

        foreach ($guide['pages'] as $page) {
            $source = base_path($guide['directory'].'/docs/'.$page.'.md');

            $this->assertFileExists($source, $guide['key'].' is missing '.$page.'.md');

            $writer->add(
                'html/'.$page.'.html',
                "<!doctype html><html><head></head><body>\n"
                    .htmlspecialchars((string) file_get_contents($source), ENT_QUOTES, 'UTF-8')
                    ."\n</body></html>\n",
            );
        }

        $build = app(Publisher::class)->publishUpload(
            $staging,
            $writer->toTarGz($this->fixtures.'/'.$guide['key'].'-'.bin2hex(random_bytes(3)).'.tar.gz'),
        )->build;

        $this->assertInstanceOf(Build::class, $build);

        $build->forceFill([
            'commit_sha' => str_repeat(substr(md5($guide['key']), 0, 1), 40),
            // §8.7.6's fragment, as the guide's own `.docup.yaml` declares it.
            'nav_json' => $this->navOf($guide),
        ])->save();

        $this->recordSource($build, $component);

        return $build;
    }

    /**
     * The guide's declared nav, read from the `.docup.yaml` it ships.
     *
     * 🛑 Read rather than restated. The committed file is what a real build
     * would lift the fragment from, so a guide that adds a page and forgets
     * its nav entry fails here instead of serving an unreachable page.
     *
     * @param  array{key: string, directory: string, pages: list<string>}  $guide
     * @return list<array{label: string, href: string}>
     */
    private function navOf(array $guide): array
    {
        /** @var array{nav?: list<array<string, string>>} $config */
        $config = Yaml::parseFile(base_path($guide['directory'].'/.docup.yaml'));

        $nodes = [];

        foreach ($config['nav'] ?? [] as $entry) {
            foreach ($entry as $label => $href) {
                $nodes[] = ['label' => (string) $label, 'href' => (string) $href];
            }
        }

        $this->assertCount(
            count($guide['pages']),
            $nodes,
            $guide['key'].': .docup.yaml nav and DogfoodPlan disagree about how many pages there are',
        );

        return $nodes;
    }

    private function stagingVersionFor(Component $component): ProjectVersion
    {
        $project = Project::query()->create([
            'slug' => 'staging-'.bin2hex(random_bytes(4)),
            'name' => 'Staging',
            'visibility' => 'public',
        ]);

        $staging = new ProjectVersion;

        $staging->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $project->id,
            'slug' => 'latest',
            'kind' => 'channel',
            'language' => 'en',
            'visibility' => 'public',
        ])->save();

        $project->forceFill(['default_version_id' => $staging->id])->save();

        (new Mounts)->attach($staging, $component, '', isPrimary: true);

        return $staging;
    }

    private function recordSource(Build $build, Component $component): void
    {
        $repositoryId = DB::table('component_sources')
            ->where('component_id', $component->id)
            ->value('repository_id');

        DB::table('build_sources')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'build_id' => $build->id,
            'repository_id' => $repositoryId,
            'component_source_id' => null,
            'ref' => 'main',
            'commit_sha' => $build->commit_sha,
            'source_path' => '',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
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

    /** @return list<string> */
    private function buildIdsOf(ProjectVersion $version): array
    {
        $manifestId = $version->refresh()->getRawOriginal('published_manifest_id');

        /** @var list<string> */
        return array_values(array_map(strval(...), DB::table('manifest_builds')
            ->where('manifest_id', $manifestId)
            ->pluck('build_id')
            ->all()));
    }

    private function manifestOf(ProjectVersion $version): ProjectVersionManifest
    {
        /** @var ProjectVersionManifest */
        return ProjectVersionManifest::query()
            ->whereKey($version->refresh()->getRawOriginal('published_manifest_id'))
            ->firstOrFail();
    }

    /**
     * Every href in a nav tree, depth first.
     *
     * @param  array<array-key, mixed>  $nodes
     * @return list<string>
     */
    private function hrefsIn(array $nodes): array
    {
        $hrefs = [];

        foreach ($nodes as $node) {
            if (! is_array($node)) {
                continue;
            }

            if (is_string($node['href'] ?? null) && $node['href'] !== '') {
                $hrefs[] = $node['href'];
            }

            if (is_array($node['children'] ?? null)) {
                $hrefs = array_merge($hrefs, $this->hrefsIn($node['children']));
            }
        }

        return $hrefs;
    }

    private function giveTheProjectADefaultSubdomain(string $projectId): void
    {
        $domainId = Uuid::v7();

        DB::table('domains')->insert([
            'id' => $domainId,
            'organisation_id' => $this->organisation->id,
            'host' => $this->host,
            'kind' => 'default_subdomain',
            'state' => 'active',
            'verified_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('domain_mounts')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'domain_id' => $domainId,
            'project_id' => $projectId,
            'path_prefix' => '',
            'mode' => 'canonical',
            'mount_exposure' => 'inherit',
            'position' => 0,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    private function docsApex(): string
    {
        $apex = config('docup.origins.docs');

        return is_string($apex) && $apex !== '' ? $apex : 'docup-docs.test';
    }

    /** @return TestResponse<Response> */
    private function getExactly(string $url): TestResponse
    {
        /** @var TestResponse<Response> */
        return TestResponse::fromBaseResponse($this->app->handle(Request::create($url, 'GET')));
    }
}
