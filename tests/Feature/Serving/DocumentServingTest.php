<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Serving;

use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
use App\Http\Middleware\RejectNonCanonicalPath;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Serving\ArtifactHandoff;
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
 * 🛑 Phase 04's first exit criterion, end to end.
 *
 * "A browser loads the P03 tree at `demo.docs.<apex>/en/latest/` with working
 * assets and anchors."
 *
 * So this publishes a real tree through the Phase 03 ingestor and then requests
 * it over HTTP on a real documentation host — the whole path, with the resolver,
 * the manifests and the handoff all in it. Nothing is faked except the artifact
 * disk.
 *
 * 🛑 What it does **not** prove is that bytes arrive: the handoff hands the edge
 * a header, and there is no edge in a test process. That is what the nginx CI
 * matrix leg and the 500 MB download criterion are for, and both are recorded as
 * owed. What this file proves is everything up to the header — which is all of
 * the authorisation, and therefore all of the part that can leak.
 */
final class DocumentServingTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private ProjectVersion $version;

    private string $host;

    private string $fixtures;

    /**
     * A GET that preserves the path exactly, trailing slash included.
     *
     * 🛑 `$this->get()` cannot express one. Laravel's
     * `MakesHttpRequests::prepareUrlForRequest()` calls `trim($uri, '/')`, so
     * `/en/latest/` arrives as `/en/latest` — and §8.9.7 makes those two
     * different requests: the first serves `index.html`, the second 302s to the
     * first. A test using `get()` would have asserted the redirect and called
     * it the document.
     *
     * So the request is built and dispatched through the HTTP kernel directly.
     * That is a faithful dispatch — the same kernel, the same middleware, the
     * same routes — and the only thing skipped is the helper that was mangling
     * the input.
     *
     * @param  array<string, string>  $headers
     * @return TestResponse<Response>
     */
    private function getExactly(string $url, array $headers = []): TestResponse
    {
        $request = Request::create($url, 'GET');

        foreach ($headers as $name => $value) {
            $request->headers->set($name, $value);
        }

        return TestResponse::fromBaseResponse($this->app->handle($request));
    }

    /**
     * The configured documentation apex, read rather than hardcoded.
     *
     * 🛑 Hardcoding it cost a debugging session. phpunit.xml declares
     * `DOCUP_DOCS_APEX=docup-docs.test`, but PHPUnit 13 removed `<env
     * force="true">` and Laravel's Dotenv loader is immutable — so the value
     * already in the container's environment from `.env` wins, and the apex in
     * a test run is whatever the container has. The routes are registered from
     * config, so a test that assumes a different apex builds hosts that match
     * no route and falls through to the dashboard's own `/`.
     *
     * tests/bootstrap.php pins APP_ENV and the database for the same reason.
     */
    private function docsApex(): string
    {
        $apex = config('docup.origins.docs');

        return is_string($apex) && $apex !== '' ? $apex : 'docup-docs.test';
    }

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');

        // The manifests are immutable and cached forever (§10.4, §8.8.1), so a
        // test publishing a second tree would otherwise read the first's.
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-serving-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $slug = 'demo-'.bin2hex(random_bytes(3));
        $this->host = $slug.'.'.$this->docsApex();

        $this->organisation = Organisation::query()->create([
            'name' => 'Serving Co',
            'slug' => 'serving-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => $slug,
            'name' => 'Demo',
            'visibility' => 'public',
        ]);

        $this->version = new ProjectVersion;
        $this->version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => 'latest',
            'kind' => 'channel',
            'language' => 'en',
            'visibility' => 'public',
        ])->save();

        // §8.6.14: the default version is an explicit stored pointer.
        $this->project->forceFill(['default_version_id' => $this->version->id])->save();

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

    // ------------------------------------------------------- the exit criterion

    public function test_a_published_tree_serves_at_its_default_subdomain(): void
    {
        $this->publish();

        // §8.9.7: the empty path redirects to the default version.
        $this->getExactly("http://{$this->host}/")
            ->assertStatus(302)
            ->assertHeader('Location', '/en/latest/')
            ->assertHeader(RejectNonCanonicalPath::RESOLVER_HEADER, 'version.default_redirect');

        // The version root resolves index.html.
        $root = $this->getExactly("http://{$this->host}/en/latest/");

        $root->assertOk();

        $accel = (string) $root->headers->get('X-Accel-Redirect');

        $this->assertStringStartsWith(ArtifactHandoff::INTERNAL_PREFIX.'/builds/', $accel);
        $this->assertStringEndsWith('/html/index.html', $accel);

        // 🛑 The application sent a header, not a body. §8.9.8: documentation
        // bytes must not be read by application code.
        $this->assertSame('', $root->getContent() === false ? '' : $root->getContent());
    }

    public function test_an_asset_beside_the_document_serves_too(): void
    {
        $this->publish();

        $response = $this->getExactly("http://{$this->host}/en/latest/assets/site.css");

        $response->assertOk();

        $this->assertStringEndsWith('/html/assets/site.css', (string) $response->headers->get('X-Accel-Redirect'));
        $this->assertSame('text/css; charset=utf-8', $response->headers->get('Content-Type'));
        $this->assertSame('inline', $response->headers->get('Content-Disposition'));
    }

    /** §8.9.11: `nosniff` always, and `attachment` for anything unknown. */
    public function test_an_unknown_type_is_served_as_an_attachment(): void
    {
        $this->publish(extra: ['html/data.bin' => 'opaque']);

        $response = $this->getExactly("http://{$this->host}/en/latest/data.bin");

        $response->assertOk();
        $this->assertSame('application/octet-stream', $response->headers->get('Content-Type'));
        $this->assertSame('attachment', $response->headers->get('Content-Disposition'));
        $this->assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
    }

    /**
     * 🛑 §8.9.13: "The system MUST serve pre-compressed sidecars where present
     * … with correct `Vary: Accept-Encoding`."
     *
     * The sidecar is published through the real §8.15.10 path, so it has been
     * decompressed, injected and recompressed at ingest — which is what keeps
     * it a valid gzip of a document that carries chrome.
     */
    public function test_a_gzip_sidecar_is_served_to_a_client_that_accepts_it(): void
    {
        $this->publish(extra: [
            'html/index.html.gz' => (string) gzencode('<html><head></head><body>demo</body></html>', 9),
        ]);

        $response = $this->getExactly("http://{$this->host}/en/latest/", ['Accept-Encoding' => 'gzip']);

        $response->assertOk();

        $this->assertStringEndsWith('/html/index.html.gz', (string) $response->headers->get('X-Accel-Redirect'));
        $this->assertSame('gzip', $response->headers->get('Content-Encoding'));

        // The type describes the DOCUMENT, not the container it arrived in.
        $this->assertSame('text/html; charset=utf-8', $response->headers->get('Content-Type'));

        // §8.9.13's Vary, without which a shared cache could hand these bytes
        // to a client that never asked for gzip.
        $this->assertStringContainsString('Accept-Encoding', (string) $response->headers->get('Vary'));
    }

    public function test_the_plain_document_is_served_when_gzip_is_refused(): void
    {
        $this->publish(extra: [
            'html/index.html.gz' => (string) gzencode('<html><head></head><body>demo</body></html>', 9),
        ]);

        $response = $this->getExactly("http://{$this->host}/en/latest/", ['Accept-Encoding' => 'gzip;q=0']);

        $response->assertOk();

        $this->assertStringEndsWith('/html/index.html', (string) $response->headers->get('X-Accel-Redirect'));
        $this->assertFalse($response->headers->has('Content-Encoding'));
    }

    /**
     * 🛑 And the sidecar has its own validator, because §8.9.12 derives the
     * ETag from the digest of what is served.
     *
     * A shared validator would let a cache answer a client that never asked for
     * gzip — `Vary` being right and the ETag being wrong, and the ETag is the
     * one caches trust.
     */
    public function test_a_sidecar_carries_a_different_etag_from_its_document(): void
    {
        $this->publish(extra: [
            'html/index.html.gz' => (string) gzencode('<html><head></head><body>demo</body></html>', 9),
        ]);

        $plain = $this->getExactly("http://{$this->host}/en/latest/", ['Accept-Encoding' => 'identity']);
        $gzip = $this->getExactly("http://{$this->host}/en/latest/", ['Accept-Encoding' => 'gzip']);

        $this->assertNotSame(
            (string) $plain->headers->get('ETag'),
            (string) $gzip->headers->get('ETag'),
        );
    }

    /**
     * 🛑 A sidecar is never a URL of its own (§8.9.13, §8.9.6).
     *
     * Serving it directly would give one document two URLs — the cache-key
     * surface §8.9.6 spends its strictness collapsing.
     */
    public function test_a_sidecar_cannot_be_requested_directly(): void
    {
        $this->publish(extra: [
            'html/guide.html.gz' => (string) gzencode('<html><head></head><body>g</body></html>', 9),
        ]);

        $this->getExactly("http://{$this->host}/en/latest/guide.html.gz")->assertNotFound();
    }

    // ----------------------------------------------------------------- caching

    /**
     * 🛑 §9.3.2's three-way check, through the real path: a public project with
     * a public version is publicly cacheable, with §9.3.3's tags.
     */
    public function test_a_public_document_is_publicly_cacheable_with_tags(): void
    {
        $this->publish();

        $response = $this->getExactly("http://{$this->host}/en/latest/");

        // Asserted as directives present, not as a prefix: Symfony canonicalises
        // `Cache-Control` into alphabetical order (`max-age=60, public`), which
        // is semantically identical and not ours to dictate.
        foreach (['Cache-Control', 'CDN-Cache-Control'] as $axis) {
            $value = (string) $response->headers->get($axis);

            $this->assertStringContainsString('public', $value, $axis);
            $this->assertStringContainsString('max-age=', $value, $axis);
            $this->assertStringNotContainsString('no-store', $value, $axis);
        }

        $tag = (string) $response->headers->get('Cache-Tag');

        foreach (['m-', 'p-', 'v-', 'b-'] as $scope) {
            $this->assertStringContainsString($scope, $tag, "§9.3.3 requires a [{$scope}] scope");
        }
    }

    /**
     * 🛑 And the kill switch: a project set to anything but public makes the
     * response private on **both** axes, with no cache tag (§8.2.10, §9.3.2).
     */
    public function test_a_non_public_project_is_private_on_both_axes(): void
    {
        $this->publish();

        $this->context->for($this->organisation->id);
        $this->project->forceFill(['visibility' => 'members'])->save();
        $this->context->forget();

        $response = $this->getExactly("http://{$this->host}/en/latest/");

        foreach (['Cache-Control', 'CDN-Cache-Control'] as $axis) {
            $value = (string) $response->headers->get($axis);

            $this->assertStringContainsString('private', $value, $axis);
            $this->assertStringContainsString('no-store', $value, $axis);
        }

        $this->assertFalse($response->headers->has('Cache-Tag'));
        $this->assertStringContainsString('Cookie', (string) $response->headers->get('Vary'));
    }

    /** 🛑 §8.9.9: "304 MUST be answerable from the manifest digest before any handoff." */
    public function test_a_matching_etag_answers_304_without_a_handoff(): void
    {
        $this->publish();

        $first = $this->getExactly("http://{$this->host}/en/latest/");
        $etag = (string) $first->headers->get('ETag');

        $this->assertMatchesRegularExpression('/^"[0-9a-f]{64}"$/', $etag, 'the ETag is the manifest sha256');

        $second = $this->getExactly("http://{$this->host}/en/latest/", ['If-None-Match' => $etag]);

        $second->assertStatus(304);

        // 🛑 No handoff header: the edge was never asked to open the file.
        $this->assertFalse(
            $second->headers->has('X-Accel-Redirect'),
            'a 304 must be answered before the handoff, not after it',
        );
    }

    public function test_a_wildcard_if_none_match_answers_304(): void
    {
        $this->publish();

        $this->getExactly("http://{$this->host}/en/latest/", ['If-None-Match' => '*'])
            ->assertStatus(304);
    }

    public function test_a_stale_etag_serves_the_document(): void
    {
        $this->publish();

        $this->getExactly("http://{$this->host}/en/latest/", ['If-None-Match' => '"'.str_repeat('0', 64).'"'])
            ->assertOk();
    }

    // ------------------------------------------------------------- the refusals

    /** 🛑 §8.9.6, through the real middleware, before anything else. */
    public function test_a_non_canonical_path_is_400_at_the_edge(): void
    {
        $this->publish();

        foreach ([
            '/en/latest/../../../etc/passwd',
            '/en//latest/',
            '/en/latest/guide.html/x.css',
            '/en/latest/%2e%2e/x.html',
        ] as $path) {
            $response = $this->getExactly("http://{$this->host}{$path}");

            $response->assertStatus(400);

            $this->assertStringStartsWith(
                'path.',
                (string) $response->headers->get(RejectNonCanonicalPath::RESOLVER_HEADER),
                "for [{$path}]",
            );

            // 🛑 The rejection is never cached. A cached 400 keyed on a
            // non-canonical path would be a cache entry whose key the attacker
            // chose — the thing being defended against, arriving by the defence.
            $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
        }
    }

    /** 🛑 §8.9.3: an unknown host is a hard 404 and never a default project. */
    public function test_an_unknown_host_is_a_hard_404(): void
    {
        $this->publish();

        $response = $this->getExactly('http://nobody.'.$this->docsApex().'/en/latest/');

        $response->assertNotFound();

        $this->assertStringContainsString(
            'host.',
            (string) $response->headers->get(RejectNonCanonicalPath::RESOLVER_HEADER),
        );
    }

    public function test_a_missing_file_is_404_from_the_manifest(): void
    {
        $this->publish();

        $this->getExactly("http://{$this->host}/en/latest/nothing-here.html")
            ->assertNotFound()
            ->assertHeader(
                RejectNonCanonicalPath::RESOLVER_HEADER,
                'file.no_match:file.not_found',
            );
    }

    public function test_an_unknown_version_is_404(): void
    {
        $this->publish();

        $this->getExactly("http://{$this->host}/en/v99/")->assertNotFound();
    }

    /** §7.3: `/_/` is reserved and unmountable. */
    public function test_the_reserved_namespace_does_not_resolve_as_documentation(): void
    {
        $this->publish();

        $this->getExactly("http://{$this->host}/_/addons")
            ->assertNotFound()
            ->assertHeader(
                RejectNonCanonicalPath::RESOLVER_HEADER,
                'path.reserved:path.reserved_segment',
            );
    }

    /**
     * 🛑 §8.10.6: an unverified custom host serves nothing.
     *
     * Asserted by flipping this project's own domain to a custom, unverified
     * one — the state a reader would hit between adding a domain and proving
     * control of it (§8.10.4).
     */
    public function test_an_unverified_custom_host_serves_nothing(): void
    {
        $this->publish();

        DB::table('domains')
            ->where('host', $this->host)
            ->update(['kind' => 'custom', 'state' => 'pending', 'verified_at' => null]);

        $this->getExactly("http://{$this->host}/en/latest/")
            ->assertNotFound()
            ->assertHeader(
                RejectNonCanonicalPath::RESOLVER_HEADER,
                'host.not_servable:host.not_servable',
            );
    }

    // ---------------------------------------------------------------- helpers

    /**
     * Publish a three-file tree through the real Phase 03 path.
     *
     * @param  array<string, string>  $extra  additional manifest-relative files
     */
    private function publish(array $extra = []): void
    {
        $writer = (new ArchiveWriter)
            ->add('html/index.html', "<!doctype html><html><head></head><body>demo</body></html>\n")
            ->add('html/guide.html', "<!doctype html><p>guide</p>\n")
            ->add('html/assets/site.css', "body{color:#222}\n");

        foreach ($extra as $path => $contents) {
            $writer->add($path, $contents);
        }

        $archive = $writer->toTarGz($this->fixtures.'/tree.tar.gz');

        $this->context->for($this->organisation->id);

        /** @var Publisher $publisher */
        $publisher = app(Publisher::class);
        $publisher->publishUpload($this->version, $archive);

        $this->context->forget();
    }

    /**
     * §8.10.2: "The **first** domain mount created for a project — normally its
     * default subdomain — MUST be created with `mode='canonical'`."
     *
     * Written here with raw inserts because Phase 04 has no domain-management
     * surface: §17 puts domain claims and verification in Phase 18 and gives
     * this phase "the `domains` and `domain_mounts` tables with their full
     * §10.5 column set (rows only)". A factory would be inventing the write
     * side early.
     */
    private function giveTheProjectADefaultSubdomain(string $slug): void
    {
        $domainId = Uuid::v7();

        DB::table('domains')->insert([
            'id' => $domainId,
            'organisation_id' => $this->organisation->id,
            'host' => $slug.'.'.$this->docsApex(),
            // An installation-owned apex needs no proof of control (§8.10.4),
            // which is why a default subdomain serves immediately.
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
            // canonical_for_project_id and is_indexable are GENERATED from this.
            'mode' => 'canonical',
            'mount_exposure' => 'inherit',
            'position' => 0,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->context->forget();
    }
}
