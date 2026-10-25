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
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Response;
use Tests\Feature\Artifacts\OfflineFormatIngestTest;
use Tests\Feature\Builds\GeneratorConformanceTest;
use Tests\Support\ArchiveWriter;
use Tests\TestCase;

/**
 * 🛑 Phase 12's serving exit criteria.
 *
 * > "A Sphinx project yields PDF, ePub and zipped HTML at documented URLs,
 * > each downloading with a `<project>-<version>` filename while the stored
 * > object path provably contains no slug. ... 🛑 An HTML file renamed `.pdf`
 * > is served with headers that prevent active content."
 *
 * The store-time half — what the object is called and where — is
 * {@see OfflineFormatIngestTest}. This is the
 * serve-time half: the URL, the filename, the headers and the refusals.
 *
 * The three archives here are published through the real Phase 03 path, so
 * what is under test is the whole chain from an uploaded tree to a response.
 * Whether Sphinx *produces* those three files is
 * {@see GeneratorConformanceTest}'s, inside the sandbox.
 */
final class DownloadServingTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private ProjectVersion $version;

    private string $host;

    private string $slug;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-downloads-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->slug = 'demo-'.bin2hex(random_bytes(3));
        $this->host = $this->slug.'.'.$this->docsApex();

        $this->organisation = Organisation::query()->create([
            'name' => 'Downloads Co',
            'slug' => 'downloads-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => $this->slug,
            'name' => 'Demo',
            'visibility' => 'public',
        ]);

        $this->version = new ProjectVersion;
        $this->version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => 'v2.1.0',
            'kind' => 'release',
            'language' => 'en',
            'visibility' => 'public',
        ])->save();

        $this->project->forceFill(['default_version_id' => $this->version->id])->save();

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
     * 🛑 "yields PDF, ePub and zipped HTML at documented URLs, each
     * downloading with a `<project>-<version>` filename".
     *
     * @param  string  $format  the URL segment
     * @param  string  $extension  what the download is called
     */
    #[DataProvider('formats')]
    public function test_each_format_downloads_with_a_project_version_filename(
        string $format,
        string $extension,
        string $contentType,
    ): void {
        $this->publishWithOfflineFormats();

        $response = $this->getExactly("http://{$this->host}/_/downloads/en/v2.1.0/{$format}");

        $response->assertOk();
        $response->assertHeader('Content-Type', $contentType);

        $expected = $this->slug.'-v2.1.0.'.$extension;

        $disposition = (string) $response->headers->get('Content-Disposition');

        $this->assertStringStartsWith('attachment; ', $disposition);
        $this->assertStringContainsString('filename="'.$expected.'"', $disposition);
        $this->assertStringContainsString("filename*=UTF-8''".rawurlencode($expected), $disposition);
    }

    /** @return array<string, array{0: string, 1: string, 2: string}> */
    public static function formats(): array
    {
        return [
            'pdf' => ['pdf', 'pdf', 'application/pdf'],
            'epub' => ['epub', 'epub', 'application/epub+zip'],
            // 🛑 The URL segment is `htmlzip` and the filename is `.zip`.
            'htmlzip' => ['htmlzip', 'zip', 'application/zip'],
        ];
    }

    /**
     * 🛑 "while the stored object path provably contains no slug".
     *
     * Asserted on the key the handoff actually names, not on the manifest —
     * the manifest is what the previous test file checks, and this is the
     * value that reaches the edge. The project slug is random per run, so a
     * key containing it could not pass by coincidence.
     */
    public function test_the_handed_off_storage_key_contains_no_slug(): void
    {
        $this->publishWithOfflineFormats();

        $response = $this->getExactly("http://{$this->host}/_/downloads/en/v2.1.0/pdf");

        $key = (string) $response->headers->get('X-Accel-Redirect');

        $this->assertNotSame('', $key, 'the response must hand off rather than read the bytes');
        $this->assertStringNotContainsString($this->slug, $key, '🛑 §8.8.1: no project slug in a storage key');
        $this->assertStringNotContainsString('v2.1.0', $key, '🛑 §8.8.1: no version slug either');
        $this->assertStringContainsString('/pdf/document.pdf', $key, '§10.3: the identifier-free leaf');
    }

    /**
     * 🛑 Phase 12's exit criterion: "An HTML file renamed `.pdf` is served
     * with headers that prevent active content."
     *
     * The published tree writes an HTML document — script tag and all — into
     * `pdf/`. Ingest stores it as `pdf/document.pdf`, which is the realistic
     * shape of this attack: a repository that can write its own build output
     * can put anything in that directory.
     *
     * Four controls, each asserted, because each closes a case the others
     * leave open. See `DownloadController::downloadHeaders()` for why one
     * would not be enough.
     */
    public function test_an_html_file_renamed_pdf_cannot_run(): void
    {
        $this->publish([
            'pdf/document.pdf' => '<html><body><script>fetch("/steal")</script></body></html>',
        ]);

        $response = $this->getExactly("http://{$this->host}/_/downloads/en/v2.1.0/pdf");

        $response->assertOk();

        // 1. The type comes from the FORMAT, not from the bytes or the name.
        $response->assertHeader('Content-Type', 'application/pdf');

        // 2. §8.9.11, always.
        $response->assertHeader('X-Content-Type-Options', 'nosniff');

        // 3. Never `inline`, whatever the type.
        $this->assertStringStartsWith(
            'attachment;',
            (string) $response->headers->get('Content-Disposition'),
        );

        // 4. The backstop for a viewer that renders in-page anyway.
        $csp = (string) $response->headers->get('Content-Security-Policy');

        $this->assertStringContainsString("default-src 'none'", $csp);
        $this->assertStringContainsString('sandbox', $csp);

        // And nothing anywhere advertises it as HTML.
        $this->assertStringNotContainsString(
            'text/html',
            (string) $response->headers->get('Content-Type'),
        );
    }

    /**
     * 🛑 Every download header survives the handoff, or the controls above
     * are present on Caddy and absent on nginx.
     *
     * §8.9.8 and §18.18: "the failure mode here is silent security
     * degradation, not a visible error." `HandoffHeaderParityTest` asserts
     * the two configurations agree; this asserts that the headers this
     * endpoint relies on are in the list they both honour.
     */
    public function test_every_security_header_this_endpoint_sets_is_preserved_through_the_handoff(): void
    {
        foreach ([
            'Content-Type',
            'Content-Disposition',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Robots-Tag',
            'Cache-Control',
        ] as $header) {
            $this->assertContains(
                $header,
                ArtifactHandoff::PRESERVED_HEADERS,
                $header.' is set by the downloads endpoint and would be dropped under nginx-accel',
            );
        }
    }

    /** A download is never indexed: §8.11's SEO answer is the HTML. */
    public function test_a_download_is_not_indexable(): void
    {
        $this->publishWithOfflineFormats();

        $this->getExactly("http://{$this->host}/_/downloads/en/v2.1.0/pdf")
            ->assertHeader('X-Robots-Tag', 'noindex');
    }

    /** §8.9.9's 304, answered from the manifest digest with no handoff. */
    public function test_a_matching_etag_answers_304_without_a_handoff(): void
    {
        $this->publishWithOfflineFormats();

        $first = $this->getExactly("http://{$this->host}/_/downloads/en/v2.1.0/pdf");
        $etag = (string) $first->headers->get('ETag');

        $this->assertNotSame('', $etag);

        $second = $this->getExactly(
            "http://{$this->host}/_/downloads/en/v2.1.0/pdf",
            ['If-None-Match' => $etag],
        );

        $second->assertStatus(304);
        $this->assertNull(
            $second->headers->get('X-Accel-Redirect'),
            '§8.9.9: answered before any handoff',
        );
    }

    /**
     * A published version that built no PDF answers 404, not 501.
     *
     * The reader asked for a document; whether one exists is a fact about
     * this version rather than about DocUp.
     */
    public function test_a_format_the_build_did_not_produce_is_404(): void
    {
        $this->publish();

        $this->getExactly("http://{$this->host}/_/downloads/en/v2.1.0/pdf")
            ->assertNotFound()
            ->assertHeader(RejectNonCanonicalPath::RESOLVER_HEADER, 'download.format_not_built');
    }

    public function test_an_unknown_version_is_404(): void
    {
        $this->publishWithOfflineFormats();

        $this->getExactly("http://{$this->host}/_/downloads/en/v99.0.0/pdf")->assertNotFound();
    }

    public function test_an_unknown_language_is_404(): void
    {
        $this->publishWithOfflineFormats();

        $this->getExactly("http://{$this->host}/_/downloads/ja/v2.1.0/pdf")->assertNotFound();
    }

    /** 🛑 §8.9.3: an unknown host never falls through to a default project. */
    public function test_an_unknown_host_is_404(): void
    {
        $this->publishWithOfflineFormats();

        $this->getExactly('http://nobody.'.$this->docsApex().'/_/downloads/en/v2.1.0/pdf')
            ->assertNotFound();
    }

    /**
     * 🛑 A format the enum does not know never reaches the manifest.
     *
     * `html` is in this list deliberately. It is a real output directory and
     * it is NOT a download — admitting it would hand a reader one arbitrary
     * file out of a site.
     */
    #[DataProvider('refusedFormats')]
    public function test_an_unknown_format_is_refused(string $format): void
    {
        $this->publishWithOfflineFormats();

        $this->getExactly("http://{$this->host}/_/downloads/en/v2.1.0/{$format}")
            ->assertNotFound();
    }

    /** @return array<string, array{0: string}> */
    public static function refusedFormats(): array
    {
        return [
            'html is not a download' => ['html'],
            'manifest is internal' => ['manifest'],
            'a format we do not build' => ['mobi'],
            'an output directory that does not exist' => ['nav'],
        ];
    }

    /**
     * 🛑 A traversal in the format segment is **400, not 404**, and the
     * difference is the point.
     *
     * §8.9.6: "Any request path not byte-identical to its own canonical
     * normalisation MUST be rejected with 400, **before any cache lookup or
     * resolution**. This is the web-cache-deception defence and its position
     * in the pipeline is the whole of its value."
     *
     * So `..%2f..%2fetc%2fpasswd` never reaches the router, let alone
     * `OfflineFormat::tryFrom()`. Asserted as 400 rather than relaxed to
     * "some 4xx", because a 404 here would mean the middleware had stopped
     * running and the enum was carrying the whole defence on its own — which
     * is exactly the degradation §8.9.6 puts the check first to prevent.
     *
     * This test was written expecting 404 and the application was right.
     */
    #[DataProvider('nonCanonicalFormats')]
    public function test_a_non_canonical_format_segment_is_rejected_at_the_edge(string $format): void
    {
        $this->publishWithOfflineFormats();

        $response = $this->getExactly("http://{$this->host}/_/downloads/en/v2.1.0/{$format}");

        $response->assertStatus(400);

        $this->assertStringStartsWith(
            'path.',
            (string) $response->headers->get(RejectNonCanonicalPath::RESOLVER_HEADER),
            'the refusal must come from the canonical-path check, not from the controller',
        );

        // 🛑 Never cached: a cached 400 keyed on a path the attacker chose is
        // the thing being defended against, arriving through the defence.
        $this->assertStringContainsString(
            'no-store',
            (string) $response->headers->get('Cache-Control'),
        );
    }

    /** @return array<string, array{0: string}> */
    public static function nonCanonicalFormats(): array
    {
        return [
            'encoded traversal' => ['..%2f..%2fetc%2fpasswd'],
            'a bare dot segment' => ['.'],
            'a double dot segment' => ['..'],
        ];
    }

    /**
     * 🛑 §8.7.19: only the primary mount emits downloads.
     *
     * With `is_primary` cleared on the only mount, the version has no primary
     * mount and therefore no downloads. Asserted because the alternative
     * implementation — take the first mount, or the one at the root — is
     * right today and silently wrong the moment Phase 13 adds a second.
     */
    public function test_a_version_with_no_primary_mount_has_no_downloads(): void
    {
        $this->publishWithOfflineFormats();

        $manifestId = DB::table('project_versions')
            ->where('id', $this->version->id)
            ->value('published_manifest_id');

        $row = DB::table('project_version_manifests')->where('id', $manifestId)->first();

        /** @var array{mounts: list<array<string, mixed>>} $mounts */
        $mounts = json_decode((string) ($row->mounts_json ?? '{}'), true, 16, JSON_THROW_ON_ERROR);

        foreach ($mounts['mounts'] as $index => $mount) {
            $mounts['mounts'][$index]['is_primary'] = false;
        }

        DB::table('project_version_manifests')
            ->where('id', $manifestId)
            ->update(['mounts_json' => json_encode($mounts, JSON_THROW_ON_ERROR)]);

        Cache::flush();

        $this->getExactly("http://{$this->host}/_/downloads/en/v2.1.0/pdf")
            ->assertNotFound()
            ->assertHeader(RejectNonCanonicalPath::RESOLVER_HEADER, 'download.no_primary_mount');
    }

    /**
     * 🛑 The download URL carries the language and the version whatever the
     * project's §8.6.9 scheme is.
     *
     * A `single_version` project serves documentation at `/file.html` with no
     * version in the path. Its downloads keep the full form, because the
     * alternative is a URL that changes when an operator changes the scheme —
     * and the one thing a bookmarked download link must survive is a setting
     * nobody told the reader about.
     */
    public function test_the_download_url_is_the_same_under_every_versioning_scheme(): void
    {
        $this->publishWithOfflineFormats();

        foreach (['lang_and_version', 'multi_version', 'single_version'] as $scheme) {
            $this->project->forceFill(['versioning_scheme' => $scheme])->save();
            Cache::flush();

            $this->getExactly("http://{$this->host}/_/downloads/en/v2.1.0/pdf")
                ->assertOk();
        }
    }

    // ---------------------------------------------------------------- helpers

    /** The three offline formats, as a real build would leave them. */
    private function publishWithOfflineFormats(): void
    {
        $this->publish([
            'pdf/document.pdf' => "%PDF-1.7\n1 0 obj\n<< >>\nendobj\n%%EOF\n",
            'epub/document.epub' => "PK\x03\x04fake epub payload",
            'htmlzip/document.zip' => "PK\x03\x04fake zip payload",
        ]);
    }

    /** @param array<string, string> $extra */
    private function publish(array $extra = []): void
    {
        $writer = (new ArchiveWriter)
            ->add('html/index.html', "<!doctype html><html><head></head><body>demo</body></html>\n");

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
     * @param  array<string, string>  $headers
     * @return TestResponse<Response>
     */
    private function getExactly(string $url, array $headers = []): TestResponse
    {
        $request = Request::create($url, 'GET');

        foreach ($headers as $name => $value) {
            $request->headers->set($name, $value);
        }

        /** @var TestResponse<Response> */
        return TestResponse::fromBaseResponse($this->app->handle($request));
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

        $this->context->forget();
    }
}
