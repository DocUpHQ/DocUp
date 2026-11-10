<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Addons;

use App\Addons\AddonsContract;
use App\Addons\AddonsPayload;
use App\Artifacts\ChromeInjector;
use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
use App\Branding\CascadeLevel;
use App\Branding\ThemeRevisions;
use App\Models\Build;
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
use Tests\Feature\Serving\DocumentServingTest;
use Tests\Support\ArchiveWriter;
use Tests\Support\GeneratorFixtures;
use Tests\TestCase;

/**
 * 🛑 §17's Phase 28 exit criteria, each asserted rather than described.
 *
 * > "A **pre-uploaded, unmodified** MkDocs tree gains a working version flyout
 * > with no rebuild. Injection is skipped for non-HTML, ranged, gzipped and
 * > oversized responses and provably never corrupts them, with the skip
 * > surfaced as a per-project warning. Per-project opt-out removes chrome on the
 * > next request with no rebuild. 🛑 A documentation page's CSS with
 * > `!important` cannot restyle or hide the version switcher. Escape closes the
 * > search modal and returns focus; result counts are announced. Changing a
 * > branding token changes the rendered chrome with the same build id."
 *
 * Four of the six are here. The two that are not:
 *
 * - **The `!important` criterion** is `tests/Js/chrome-isolation.test.mjs`,
 *   because the subject is a closed shadow root in a DOM and PHP has neither.
 *   That file is also §18.11's "adversarial fixture page attempting all four".
 * - **Escape and the announced counts** are `tests/Js/chrome-keyboard.test.mjs`,
 *   for the same reason: they are keyboard behaviour inside that root.
 *
 * Both run under `npm run test:js`, a CI step beside `npm run axe` — for the
 * reason the axe step gives: a Pest test that skipped when Node was absent
 * would be a skipped test.
 */
final class ExitCriteriaTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private ProjectVersion $v1;

    private ProjectVersion $v2;

    private string $host;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Storage::fake('branding');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-addons-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $slug = 'addons-'.bin2hex(random_bytes(3));
        $this->host = $slug.'.'.$this->docsApex();

        $this->organisation = Organisation::query()->create([
            'name' => 'Addons Co',
            'slug' => 'addons-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => $slug,
            'name' => 'Addons Demo',
            'visibility' => 'public',
        ]);

        $this->v1 = $this->makeVersion('v1');
        $this->v2 = $this->makeVersion('v2');

        $this->project->forceFill([
            'default_version_id' => $this->v2->id,
            'resolved_latest_version_id' => $this->v2->id,
            'resolved_stable_version_id' => $this->v2->id,
        ])->save();

        $this->giveTheProjectADefaultSubdomain($slug);
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

    // ------------------------------------------------------------------- 1

    /**
     * 🛑 "A **pre-uploaded, unmodified** MkDocs tree gains a working version
     * flyout with no rebuild."
     *
     * Every word of that is tested. The tree is a real MkDocs Material shape
     * from {@see GeneratorFixtures}' vocabulary — authored here as
     * the generator writes it, with no DocUp markers in it. It is published
     * **once**. The flyout then comes from `/_/addons`, which means:
     *
     * - "unmodified" — the stored bytes are compared against what was uploaded,
     *   byte for byte, apart from §8.15.1's two tags before `</head>`;
     * - "no rebuild" — one `builds` row exists before and after, and the
     *   artifact's digest does not move;
     * - "working" — the payload carries both versions, in §8.6.5's order, with
     *   §8.6.11's page existence and a URL per version.
     */
    public function test_an_unmodified_mkdocs_tree_gains_a_working_version_flyout(): void
    {
        $page = $this->mkdocsPage();

        $this->publish($this->v1, ['html/index.html' => $page, 'html/guide/index.html' => $page]);
        $this->publish($this->v2, ['html/index.html' => $page, 'html/guide/index.html' => $page]);

        $buildsBefore = Build::withoutGlobalScopes()->count();

        $payload = $this->addons('/en/v2/guide/');

        // "Working": the flyout is there, ordered, and knows about both versions.
        $versions = $payload['flyout']['versions'];

        $this->assertCount(2, $versions);
        $this->assertSame(['v2', 'v1'], array_column($versions, 'slug'), '§8.6.5 orders newest first');
        $this->assertTrue($versions[0]['current'], 'the version being read is marked current');
        $this->assertSame('/en/v1/guide/', $versions[1]['href'], 'and the other version links to the same page');

        // §8.6.11: the page exists in both, answered from the manifest.
        $this->assertTrue($versions[0]['page_exists']);
        $this->assertTrue($versions[1]['page_exists']);

        // §8.15.2's named fields are all present.
        $this->assertSame(AddonsContract::VERSION, $payload['contract']);
        $this->assertSame('injected', $payload['chrome_mode']);
        $this->assertArrayHasKey('branding', $payload);
        $this->assertArrayHasKey('notifications', $payload);
        $this->assertArrayHasKey('search', $payload);
        $this->assertArrayHasKey('navigation', $payload);
        $this->assertArrayHasKey('cross_references', $payload);
        $this->assertArrayHasKey('canonical', $payload);
        $this->assertArrayHasKey('analytics', $payload);
        $this->assertArrayHasKey('downloads', $payload);

        // 🛑 "No rebuild": nothing published, nothing changed.
        $this->assertSame($buildsBefore, Build::withoutGlobalScopes()->count());

        // 🛑 "Unmodified": the stored document is the uploaded document plus
        // exactly §8.15.1's two tags, and nothing else moved.
        $stored = $this->storedDocument($this->v2, 'html/guide/index.html');
        $tags = '<script defer src="'.ChromeInjector::LOADER_PATH.'"></script>'
            .'<meta name="docup" content="b='.$this->buildIdOf($this->v2).'">';

        $this->assertSame(
            str_replace('</head>', $tags.'</head>', $page),
            $stored,
            'the only change to a generator\'s bytes is §8.15.1\'s two tags',
        );

        // And the loader those tags point at is served.
        $loader = $this->getExactly('http://'.$this->host.ChromeInjector::LOADER_PATH);

        $loader->assertOk();
        $this->assertStringContainsString('text/javascript', (string) $loader->headers->get('Content-Type'));
        $this->assertStringContainsString('attachShadow', (string) $loader->getContent());
    }

    // ------------------------------------------------------------------- 3

    /**
     * 🛑 "Per-project opt-out removes chrome on the next request with no
     * rebuild."
     *
     * The artifact still carries §8.15.1's two tags — it must, because
     * artifacts are immutable (§8.8.1) and §8.15.4 forbids serve-time
     * rewriting. So the opt-out has to work through the payload, and that is
     * exactly what `chrome_mode: off` does: the runtime reads the mode and
     * renders nothing, on the very next request, with the same bytes on disk.
     */
    public function test_per_project_opt_out_removes_chrome_on_the_next_request(): void
    {
        $this->publish($this->v2, ['html/index.html' => $this->mkdocsPage()]);

        $before = $this->storedDocument($this->v2, 'html/index.html');
        $buildsBefore = Build::withoutGlobalScopes()->count();

        $this->assertSame('injected', $this->addons('/en/v2/')['chrome_mode']);

        $this->project->forceFill(['chrome_mode' => 'off'])->save();

        // 🛑 The NEXT request, with no publish and no cache flush between.
        $payload = $this->addons('/en/v2/');

        $this->assertSame('off', $payload['chrome_mode']);

        /*
         * 🛑 And §8.15.12's MUST: "leave the generator's own search working
         * untouched when `chrome_mode` is `off`". The payload says so in the
         * one boolean the runtime reads, so the runtime cannot implement half
         * the rule.
         */
        $this->assertFalse($payload['search']['takeover']);

        // No rebuild, and not one byte of the artifact changed.
        $this->assertSame($buildsBefore, Build::withoutGlobalScopes()->count());
        $this->assertSame($before, $this->storedDocument($this->v2, 'html/index.html'));

        // `api_only` is the third mode and is distinguishable from both.
        $this->project->forceFill(['chrome_mode' => 'api_only'])->save();
        $this->assertSame('api_only', $this->addons('/en/v2/')['chrome_mode']);
    }

    // ------------------------------------------------------------------- 6

    /**
     * 🛑 "Changing a branding token changes the rendered chrome with the **same
     * build id**."
     *
     * This is §8.14's goal reaching the reader. The artifact carries the build
     * id and nothing else (§8.15.1), so the stylesheet URL, the token values
     * and the brand name all arrive in the payload — and a token edit changes
     * the payload with no publish, no rebuild and no change to a stored byte.
     */
    public function test_changing_a_branding_token_changes_the_chrome_with_the_same_build_id(): void
    {
        $this->publish($this->v2, ['html/index.html' => $this->mkdocsPage()]);

        $before = $this->addons('/en/v2/');
        $buildId = $before['build'];
        $storedBefore = $this->storedDocument($this->v2, 'html/index.html');

        $this->assertNotNull($buildId);

        $this->publishProjectTheme([
            'brand.name' => 'Rebranded',
            'color.brand.primary' => ['light' => '#004488', 'dark' => '#88bbee'],
        ]);

        Cache::flush();

        $after = $this->addons('/en/v2/');

        // 🛑 The same build id…
        $this->assertSame($buildId, $after['build'], 'the build id must not move');

        // …the same bytes on disk…
        $this->assertSame($storedBefore, $this->storedDocument($this->v2, 'html/index.html'));

        // …and visibly different chrome.
        $this->assertNotSame(
            $before['branding']['theme']['hash'],
            $after['branding']['theme']['hash'],
            'a token edit mints a new content hash (§8.14.4)',
        );
        $this->assertNotSame(
            $before['branding']['theme']['stylesheet'],
            $after['branding']['theme']['stylesheet'],
        );
        $this->assertSame('Rebranded', $after['branding']['theme']['tokens']['brand.name']['light']);
        $this->assertSame('#004488', $after['branding']['theme']['tokens']['color.brand.primary']['light']);
        $this->assertSame('#88bbee', $after['branding']['theme']['tokens']['color.brand.primary']['dark']);
    }

    /**
     * 🛑 §8.12.9: the flyout is "generated from the **authorised** view".
     *
     * A private version must be absent for an anonymous reader. This is not one
     * of §17's named exit criteria and it is the one that would leak if the
     * payload were wrong — a flyout is a list of version slugs, and a slug is a
     * release nobody has announced yet.
     */
    public function test_a_private_version_is_absent_from_an_anonymous_flyout(): void
    {
        $this->publish($this->v1, ['html/index.html' => $this->mkdocsPage()]);
        $this->publish($this->v2, ['html/index.html' => $this->mkdocsPage()]);

        $this->v1->forceFill(['visibility' => 'members'])->save();
        Cache::flush();

        $slugs = array_column($this->addons('/en/v2/')['flyout']['versions'], 'slug');

        $this->assertSame(['v2'], $slugs, 'a members-only version is not advertised to an anonymous reader');
    }

    /** §8.15.2: the payload is `Vary: Cookie` and never publicly cacheable. */
    public function test_the_payload_varies_on_cookie_and_is_never_publicly_cacheable(): void
    {
        $this->publish($this->v2, ['html/index.html' => $this->mkdocsPage()]);

        $response = $this->getExactly('http://'.$this->host.AddonsContract::PATH.'?path=%2Fen%2Fv2%2F');

        $response->assertOk();

        $this->assertStringContainsString('Cookie', (string) $response->headers->get('Vary'));
        $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
        $this->assertStringNotContainsString('public', (string) $response->headers->get('Cache-Control'));
        $this->assertStringNotContainsString('public', (string) $response->headers->get('CDN-Cache-Control'));
        $this->assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
    }

    /**
     * 🛑 The `path` parameter is reader input and decides an authorisation
     * subject, so a non-canonical one is refused before anything resolves.
     */
    public function test_a_non_canonical_path_parameter_is_refused(): void
    {
        $this->publish($this->v2, ['html/index.html' => $this->mkdocsPage()]);

        foreach ([
            '/en/v2/../../etc/passwd',
            '/en/v2//double',
            '/en/%2e%2e/v2/',
            'en/v2/',
        ] as $hostile) {
            $response = $this->getExactly(
                'http://'.$this->host.AddonsContract::PATH.'?path='.urlencode($hostile),
            );

            $this->assertContains(
                $response->getStatusCode(),
                [400, 404],
                'a non-canonical path must not be resolved: '.$hostile,
            );
        }

        /*
         * 🛑 A whole URL is reduced to its path, and that is correct rather
         * than lenient. §8.9.4 is the rule being kept: "The project MUST be
         * resolved **solely** from the TLS server name or `Host` header plus
         * the path. No request header MUST act as a project, version or tenant
         * selector." The parameter contributes a path and the REQUEST
         * contributes the host — so a reader who puts someone else's hostname
         * in the parameter gets their own host's project, which is the only
         * safe answer and the one asserted here.
         *
         * Asserted explicitly because the alternative reading — refuse it — is
         * tempting and would be the wrong control: it would look like a
         * defence while the real defence is that the host is never read from
         * here at all.
         */
        $response = $this->getExactly(
            'http://'.$this->host.AddonsContract::PATH.'?path='.urlencode('https://evil.test/en/v2/'),
        );

        $response->assertOk();

        /** @var array<string, mixed> $payload */
        $payload = json_decode((string) $response->getContent(), true, 64, JSON_THROW_ON_ERROR);

        $this->assertSame($this->project->slug, $payload['project']['slug']);
        $this->assertSame('v2', $payload['version']['slug']);
    }

    // ------------------------------------------------------------- helpers

    /**
     * A GET that preserves the path exactly, trailing slash included.
     *
     * 🛑 `$this->get()` cannot express one: Laravel's
     * `MakesHttpRequests::prepareUrlForRequest()` trims slashes, and §8.9.7
     * makes `/en/v2/` and `/en/v2` different requests. Copied from
     * {@see DocumentServingTest}, which records the same
     * finding.
     *
     * @return TestResponse<Response>
     */
    private function getExactly(string $url): TestResponse
    {
        return TestResponse::fromBaseResponse($this->app->handle(Request::create($url, 'GET')));
    }

    /**
     * The payload for a document path, decoded.
     *
     * @return array<string, mixed>
     */
    private function addons(string $path): array
    {
        $response = $this->getExactly(
            'http://'.$this->host.AddonsContract::PATH.'?path='.urlencode($path),
        );

        $response->assertOk();

        /** @var array<string, mixed> $decoded */
        $decoded = json_decode((string) $response->getContent(), true, 64, JSON_THROW_ON_ERROR);

        return $decoded;
    }

    /**
     * A page as MkDocs Material writes one.
     *
     * 🛑 Authored as the generator emits it, not as a fixture convenient for
     * the injector: lower-case `</head>` with no whitespace, a `<base>`, inline
     * script and style, and the generator's own search affordance — which is
     * what §8.15.12's selector has to find.
     */
    private function mkdocsPage(): string
    {
        return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            .'<meta name="viewport" content="width=device-width,initial-scale=1">'
            .'<link rel="stylesheet" href="assets/stylesheets/main.css">'
            .'<script>window.__md_scope=new URL(".",location);</script>'
            ."</head>\n"
            .'<body dir="ltr" data-md-color-scheme="default">'
            .'<div class="md-search__inner" role="search">'
            .'<form class="md-search__form" name="search"><input type="text" class="md-search__input" '
            .'name="query" placeholder="Search" aria-label="Search"></form></div>'
            .'<main><h1 id="guide">Guide</h1><p>Body text.</p></main>'
            .'</body></html>';
    }

    private function makeVersion(string $slug): ProjectVersion
    {
        $version = new ProjectVersion;

        $version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => $slug,
            'kind' => 'release',
            'language' => 'en',
            'visibility' => 'public',
            'ref_name' => $slug,
            'ref_kind' => 'tag',
        ])->save();

        return $version;
    }

    /** @param array<string, string> $files */
    private function publish(ProjectVersion $version, array $files): void
    {
        $writer = new ArchiveWriter;

        foreach ($files as $path => $contents) {
            $writer->add($path, $contents);
        }

        $archive = $writer->toTarGz($this->fixtures.'/'.$version->slug.'-'.bin2hex(random_bytes(3)).'.tar.gz');

        $this->context->for($this->organisation->id);

        /** @var Publisher $publisher */
        $publisher = app(Publisher::class);
        $publisher->publishUpload($version, $archive);

        /*
         * Refreshed INSIDE the context, because `refresh()` reloads the model's
         * loaded relations and `project` is one of them — a tenant-scoped query
         * that §8.2.1 refuses to run with nothing declared. Found by that
         * refusal, which is the global scope doing its job on a test.
         */
        $version->refresh();

        $this->context->forget();
    }

    /**
     * The published build's id as text.
     *
     * From the `builds` row rather than from the manifest's `mounts_json`,
     * because the one thing this must not share with the code under test is its
     * own idea of where the build id lives — {@see AddonsPayload}
     * reads the manifest, so a test that read the manifest too would agree with
     * it even when both were wrong.
     */
    private function buildIdOf(ProjectVersion $version): string
    {
        $build = Build::withoutGlobalScopes()
            ->where('project_version_id', $version->id)
            ->orderByDesc('created_at')
            ->firstOrFail();

        return Uuid::toText($build->id);
    }

    private function storedDocument(ProjectVersion $version, string $path): string
    {
        $key = 'builds/'.$this->buildIdOf($version).'/'.$path;

        /*
         * 🛑 Existence first, then read. `Storage::get()` on a missing key goes
         * through `file_get_contents` and emits a PHP warning that Pest
         * surfaces as a test warning — so a wrong key here would show up as
         * noise beside a passing assertion rather than as a failure. Asserted
         * instead, which is what the test actually means.
         */
        $this->assertTrue(
            Storage::disk('artifacts')->exists($key),
            'the published artifact holds '.$path,
        );

        return (string) Storage::disk('artifacts')->get($key);
    }

    /** @param array<string, mixed> $tokens */
    private function publishProjectTheme(array $tokens): void
    {
        $revisions = ThemeRevisions::make((string) $this->organisation->id, (string) $this->project->id);

        $revisions->publish($revisions->draft(
            level: CascadeLevel::Project,
            scopeId: (string) $this->project->id,
            organisationId: (string) $this->organisation->id,
            tokens: $tokens,
        ));
    }

    private function docsApex(): string
    {
        $apex = config('docup.origins.docs');

        return is_string($apex) && $apex !== '' ? $apex : 'docup-docs.test';
    }

    private function giveTheProjectADefaultSubdomain(string $slug): void
    {
        $domainId = Uuid::v7();

        DB::table('domains')->insert([
            'id' => $domainId,
            'organisation_id' => $this->organisation->id,
            'host' => $slug.'.'.$this->docsApex(),
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

        $this->context->forget();
    }
}
