<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Serving;

use App\Artifacts\Publisher;
use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Composition\Components;
use App\Composition\Mounts;
use App\Http\Middleware\RejectNonCanonicalPath;
use App\Models\Build;
use App\Models\Component;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Tests\Support\ArchiveWriter;
use Tests\TestCase;

/**
 * 🛑 Phase 14's serving surfaces: §8.7.16's cross-reference namespace,
 * §8.7.21's `/_/composition`, and §8.7.15's shadow redirects.
 *
 * All three are reached through the real route table and the real
 * middleware stack, because each one lives under `/_/` — §7.3's reserved,
 * unmountable namespace — and the thing most likely to be wrong about a
 * reserved route is its position relative to the catch-all, which only a
 * real request can show.
 */
final class CompositionServingTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private ProjectVersion $version;

    private Components $components;

    private Mounts $mounts;

    /** @var array<string, Component> */
    private array $parts = [];

    private string $host;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-xref-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $slug = 'composed-'.bin2hex(random_bytes(3));
        $this->host = $slug.'.'.$this->docsApex();

        $this->organisation = Organisation::query()->create([
            'name' => 'Composed Co',
            'slug' => 'composed-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => $slug,
            'name' => 'Composed',
            'visibility' => 'public',
        ]);

        $this->version = new ProjectVersion;
        $this->version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => 'v1',
            'kind' => 'channel',
            'language' => 'en',
            'visibility' => 'public',
        ])->save();

        $this->project->forceFill(['default_version_id' => $this->version->id])->save();

        $this->components = new Components;
        $this->mounts = new Mounts;

        $this->giveTheProjectADefaultSubdomain();
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
     * 🛑 §8.7.16: "Cross-component links MUST resolve at serve time through
     * `/_/x/{component_key}/{path}` against the published manifest, 302'd".
     */
    public function test_a_cross_component_reference_redirects_to_where_it_is_mounted(): void
    {
        $this->composeTwoComponents();

        $this->getExactly("http://{$this->host}/_/x/{$this->parts['glossary']->key}/terms.html")
            ->assertStatus(302)
            ->assertHeader('Location', '/en/v1/glossary/terms.html');
    }

    /**
     * The redirect follows the MOUNT, not the component, which is what
     * makes a recomposition invisible to the author who wrote the link.
     */
    public function test_moving_the_mount_moves_the_redirect_without_touching_the_build(): void
    {
        $this->composeTwoComponents();

        $mount = $this->version->mounts()
            ->where('component_id', $this->parts['glossary']->id)
            ->firstOrFail();

        $this->mounts->detach($mount);
        $this->mounts->attach($this->version, $this->parts['glossary'], 'reference/terms', isPrimary: false);

        /*
         * 🛑 Refreshed first. SPEC 8.8.4's compare-and-swap reads the
         * pointer the caller captured, and this model was loaded before the
         * first publish — so republishing from it would lose the race
         * against itself, the test would still pass, and it would be
         * asserting that nothing changed.
         */
        $republished = app(Publisher::class)->publishExistingBuild(
            $this->version->refresh(),
            $this->latestBuildOf($this->parts['handbook']),
        );

        $this->assertTrue($republished->published, 'the recomposition actually published');

        Cache::flush();

        $this->getExactly("http://{$this->host}/_/x/{$this->parts['glossary']->key}/terms.html")
            ->assertStatus(302)
            ->assertHeader('Location', '/en/v1/reference/terms/terms.html');
    }

    /** A component this version does not mount is a 404, not a guess. */
    public function test_a_reference_to_an_unmounted_component_is_not_found(): void
    {
        $this->composeTwoComponents();

        $this->getExactly("http://{$this->host}/_/x/not-a-component/terms.html")
            ->assertNotFound();
    }

    /**
     * 🛑 §8.7.16: "`objects.inv` and a per-component cross-reference map
     * MUST be served **directly at a stable path with no redirect**, so
     * Sphinx intersphinx never depends on redirect-following."
     *
     * The assertion is on the **status**, not on the body: a 200 is the
     * whole requirement, and a 302 here is the failure that breaks
     * somebody else's build a year later.
     */
    public function test_objects_inv_is_served_directly_with_no_redirect(): void
    {
        $this->composeTwoComponents(withInventory: true);

        $response = $this->getExactly(
            "http://{$this->host}/_/x/{$this->parts['glossary']->key}/objects.inv",
        );

        $response->assertOk();
        $response->assertHeader('X-Content-Type-Options', 'nosniff');
        $this->assertSame(
            'application/octet-stream',
            $response->headers->get('Content-Type'),
            'a browser must not try to render an inventory',
        );
    }

    /** A component with no inventory answers 404, never a broken handoff. */
    public function test_a_component_without_an_inventory_answers_not_found(): void
    {
        $this->composeTwoComponents();

        $this->getExactly("http://{$this->host}/_/x/{$this->parts['glossary']->key}/objects.inv")
            ->assertNotFound();
    }

    /** The map is served directly too, for the same reason. */
    public function test_the_cross_reference_map_is_served_directly(): void
    {
        $this->composeTwoComponents();

        $response = $this->getExactly(
            "http://{$this->host}/_/x/{$this->parts['glossary']->key}/_xref.json",
        );

        $response->assertOk();

        /** @var array{components: array<string, array<string, mixed>>} $payload */
        $payload = $response->json();

        $this->assertArrayHasKey($this->parts['glossary']->key, $payload['components']);
        $this->assertSame('glossary', $payload['components'][$this->parts['glossary']->key]['mount_path']);
    }

    /**
     * 🛑 §8.7.21: "the resolved composition of every published version —
     * each component, resolved ref, commit, build id and build time — at
     * `/_/composition`".
     */
    public function test_the_composition_endpoint_names_every_component_and_commit(): void
    {
        $this->composeTwoComponents();

        $response = $this->getExactly("http://{$this->host}/_/composition");
        $response->assertOk();

        /** @var array{versions: list<array<string, mixed>>} $payload */
        $payload = $response->json();

        $this->assertCount(1, $payload['versions']);

        $version = $payload['versions'][0];

        $this->assertSame('v1', $version['version']);
        $this->assertCount(2, $version['components']);

        $keys = array_map(
            static fn (array $component): string => (string) $component['component'],
            $version['components'],
        );

        sort($keys, SORT_STRING);
        $expected = [$this->parts['glossary']->key, $this->parts['handbook']->key];
        sort($expected, SORT_STRING);

        $this->assertSame($expected, $keys);

        foreach ($version['components'] as $component) {
            $this->assertNotNull($component['commit'], 'every component names its commit');
            $this->assertNotNull($component['build'], 'and the build that produced it');
        }
    }

    /**
     * 🛑 A non-public version is absent, and that is fail-closed rather
     * than final.
     *
     * Reader authorisation is Phase 21's, so there is no actor to ask about
     * yet. Listing a `members` version's components would disclose which
     * repositories feed a private manual to anyone who can reach the host.
     */
    public function test_a_private_version_is_absent_from_the_composition(): void
    {
        $this->composeTwoComponents();

        $this->version->forceFill(['visibility' => AccessLevel::Members->value])->save();
        Cache::flush();

        $response = $this->getExactly("http://{$this->host}/_/composition");
        $response->assertOk();

        /** @var array{versions: list<array<string, mixed>>} $payload */
        $payload = $response->json();

        $this->assertSame([], $payload['versions']);
    }

    /**
     * 🛑 §8.7.15: "on explicit audited override the system MUST
     * auto-generate redirect rows for every shadowed path".
     *
     * The handbook serves `guide/legacy.html`; a second component is then
     * mounted at `guide` with the override. The legacy page is unreachable
     * by construction — §8.7.12's longest-prefix match sends `/guide/...`
     * to the deeper mount — so without a redirect a reader's bookmark
     * becomes a 404, silently.
     */
    public function test_a_shadowed_path_redirects_instead_of_404ing(): void
    {
        $handbook = $this->makeComponent('handbook');
        $guide = $this->makeComponent('guide');

        $this->mounts->attach($this->version, $handbook, '', isPrimary: true);
        $this->buildFor($handbook, ['html/index.html', 'html/guide/legacy.html']);

        $this->mounts->attach(
            $this->version,
            $guide,
            'guide',
            isPrimary: false,
            shadowingOverride: true,
        );
        $this->buildFor($guide, ['html/index.html']);

        app(Publisher::class)->publishExistingBuild($this->version, $this->latestBuildOf($handbook));
        Cache::flush();

        $this->getExactly("http://{$this->host}/en/v1/guide/legacy.html")
            ->assertStatus(302)
            ->assertHeader('Location', '/en/v1/guide/')
            ->assertHeader(RejectNonCanonicalPath::RESOLVER_HEADER, 'composition.shadowed_path');

        // 🛑 And a path the deeper mount DOES serve is untouched: the
        // redirect map holds only paths that disappeared, so it can never
        // shadow a real page.
        $this->getExactly("http://{$this->host}/en/v1/guide/")->assertOk();
    }

    /**
     * 🛑 A manifest written before Phase 14 still serves.
     *
     * §8.1.11's stability promise applies to the stored document as much
     * as to the API: `docup.version-manifest/1` has no `component_key`, no
     * `shadow_redirects` and no `resolution`, and an installation upgrading
     * into this phase is serving thousands of them. The readers have to
     * treat every new key as absent-means-nothing rather than
     * absent-means-broken, and this is the test that says so.
     */
    public function test_a_manifest_written_before_this_phase_still_serves(): void
    {
        $this->composeTwoComponents();

        $manifestId = $this->version->refresh()->getRawOriginal('published_manifest_id');

        /** @var object{mounts_json: string} $row */
        $row = DB::table('project_version_manifests')->where('id', $manifestId)->first();

        /** @var array{mounts: list<array<string, mixed>>} $decoded */
        $decoded = json_decode($row->mounts_json, true, 16, JSON_THROW_ON_ERROR);

        // Rebuilt as exactly the Phase 03 shape: the five keys that existed,
        // and the schema identifier that went with them. Rebuilt rather than
        // pruned, so a key added later cannot survive by being forgotten here
        // and make this test quietly stop testing the old document.
        $mounts = [];

        foreach ($decoded['mounts'] as $mount) {
            $mounts[] = [
                'mount_path' => $mount['mount_path'],
                'component_id' => $mount['component_id'],
                'build_id' => $mount['build_id'],
                'is_primary' => $mount['is_primary'],
                'min_access' => $mount['min_access'],
            ];
        }

        DB::table('project_version_manifests')
            ->where('id', $manifestId)
            ->update(['mounts_json' => json_encode(
                ['schema' => 'docup.version-manifest/1', 'mounts' => $mounts],
                JSON_THROW_ON_ERROR,
            )]);

        Cache::flush();

        $this->getExactly("http://{$this->host}/en/v1/")->assertOk();
        $this->getExactly("http://{$this->host}/en/v1/glossary/terms.html")->assertOk();

        // The endpoints that read the new keys degrade rather than break:
        // a composition with no `component_key` names no component, and a
        // 500 here would take the whole auditor's view down on upgrade.
        $this->getExactly("http://{$this->host}/_/composition")->assertOk();
    }

    // ---------------------------------------------------------------- helpers

    /** A handbook at the root and a glossary at `glossary`. */
    private function composeTwoComponents(bool $withInventory = false): void
    {
        $this->parts['handbook'] = $this->makeComponent('handbook');
        $this->parts['glossary'] = $this->makeComponent('glossary');

        $this->mounts->attach($this->version, $this->parts['handbook'], '', isPrimary: true);
        $this->mounts->attach($this->version, $this->parts['glossary'], 'glossary', isPrimary: false);

        $this->buildFor($this->parts['handbook'], ['html/index.html']);
        $this->buildFor(
            $this->parts['glossary'],
            $withInventory
                ? ['html/index.html', 'html/terms.html', 'html/objects.inv']
                : ['html/index.html', 'html/terms.html'],
        );

        app(Publisher::class)->publishExistingBuild(
            $this->version,
            $this->latestBuildOf($this->parts['handbook']),
        );

        Cache::flush();
    }

    private function makeComponent(string $key): Component
    {
        return $this->components->register(
            organisationId: $this->organisation->id,
            key: $key.'-'.bin2hex(random_bytes(3)),
            name: ucfirst($key),
            minAccess: AccessLevel::Public,
        );
    }

    /**
     * A real ingested build, on a throwaway version of its own.
     *
     * @param  list<string>  $paths
     */
    private function buildFor(Component $component, array $paths): Build
    {
        $project = Project::query()->create([
            'slug' => 'staging-'.bin2hex(random_bytes(4)),
            'name' => 'Staging',
            'visibility' => 'public',
        ]);

        $staging = new ProjectVersion;
        $staging->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $project->id,
            'slug' => 'latest',
            'kind' => 'channel',
            'language' => 'en',
            'visibility' => 'public',
        ])->save();

        $project->forceFill(['default_version_id' => $staging->id])->save();

        $this->mounts->attach($staging, $component, '', isPrimary: true);

        $writer = new ArchiveWriter;

        foreach ($paths as $path) {
            $writer->add($path, "<!doctype html><html><head></head><body>{$path}</body></html>\n");
        }

        $outcome = app(Publisher::class)->publishUpload(
            $staging,
            $writer->toTarGz($this->fixtures.'/t-'.bin2hex(random_bytes(4)).'.tar.gz'),
        );

        $build = $outcome->build;
        $this->assertInstanceOf(Build::class, $build);

        $build->forceFill(['commit_sha' => str_repeat('a', 40)])->save();

        DB::table('build_sources')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'build_id' => $build->id,
            'repository_id' => $this->repositoryId(),
            'component_source_id' => null,
            'ref' => 'main',
            'commit_sha' => str_repeat('a', 40),
            'source_path' => 'docs',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $build;
    }

    /** @return string raw 16 bytes */
    private function repositoryId(): string
    {
        $existing = DB::table('repositories')
            ->where('organisation_id', $this->organisation->id)
            ->value('id');

        if (is_string($existing)) {
            return $existing;
        }

        $id = Uuid::v7();

        DB::table('repositories')->insert([
            'id' => $id,
            'organisation_id' => $this->organisation->id,
            'provider' => 'github',
            'provider_host' => 'github.com',
            'clone_url' => 'https://github.com/docup/x.git',
            'normalised_url' => 'https://github.com/docup/x',
            'default_branch' => 'main',
            'provider_repo_id' => (string) random_int(1000, 99999),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $id;
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

    /** @return TestResponse<Response> */
    private function getExactly(string $url): TestResponse
    {
        /** @var TestResponse<Response> */
        return TestResponse::fromBaseResponse($this->app->handle(Request::create($url, 'GET')));
    }

    private function docsApex(): string
    {
        $apex = config('docup.origins.docs');

        return is_string($apex) && $apex !== '' ? $apex : 'docup-docs.test';
    }

    private function giveTheProjectADefaultSubdomain(): void
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
            'project_id' => $this->project->id,
            'path_prefix' => '',
            'mode' => 'canonical',
            'mount_exposure' => 'inherit',
            'position' => 0,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }
}
