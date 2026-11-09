<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Addons;

use App\Addons\ChromeHealth;
use App\Addons\ChromeReingest;
use App\Artifacts\ChromeInjector;
use App\Artifacts\InjectionOutcome;
use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
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
use Tests\Support\ArchiveWriter;
use Tests\TestCase;

/**
 * 🛑 §17's Phase 28 exit criterion two, in full:
 *
 * > "Injection is skipped for non-HTML, ranged, gzipped and oversized responses
 * > and **provably never corrupts them**, with the skip surfaced as a
 * > per-project warning."
 *
 * Five claims, and each needs a different kind of proof:
 *
 * | Claim | How it is proven here |
 * |---|---|
 * | non-HTML | A CSS, a PNG, a JSON and a `.js` published through the real ingestor; the stored bytes are compared **byte for byte** with what went in |
 * | oversized | A document over the configured ceiling; same byte comparison, plus the outcome recorded as `refused_too_large` |
 * | gzipped | 🛑 §8.15.10's disposition: decompressed, injected, recompressed. The sidecar is **not** skipped — it is handled — so what is proven is that it still decompresses to a valid document and that the document carries the tags |
 * | ranged | A `Range` request served through the real edge handoff, asserted as untouched. Injection happens at **ingest**, so a ranged response cannot be injected by construction — this proves the construction holds end to end |
 * | the warning | {@see ChromeHealth} on the real project and build API surfaces |
 *
 * ## 🛑 "Provably never corrupts them" is a byte comparison and nothing less
 *
 * Each skipped class asserts `assertSame($original, $stored)` on the exact
 * bytes. A test that checked only "the file still exists" or "the type is still
 * right" would pass for an injector that appended a newline to every stylesheet
 * on the installation — and a stylesheet with a stray byte is a page that looks
 * broken for a reason nobody can find.
 */
final class InjectionSafetyTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private ProjectVersion $version;

    private string $host;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-injection-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $slug = 'inject-'.bin2hex(random_bytes(3));
        $this->host = $slug.'.'.$this->docsApex();

        $this->organisation = Organisation::query()->create([
            'name' => 'Injection Co',
            'slug' => 'inject-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => $slug,
            'name' => 'Injection Demo',
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

    /**
     * 🛑 Non-HTML is skipped and **provably uncorrupted**.
     *
     * Four types with four different reasons to be fragile: a stylesheet where a
     * stray byte is a visible defect, a PNG where one is a decode failure, a
     * JSON where one is a parse error, and a JavaScript file that contains the
     * literal string `</head>` — which is the case a byte-level search could
     * get wrong if it ever ran on something other than HTML.
     */
    public function test_non_html_is_never_touched(): void
    {
        $files = [
            'html/assets/site.css' => "body{color:#222}\n/* </head> */\n",
            'html/assets/logo.png' => self::png(),
            'html/search/index.json' => '{"docs":[{"title":"</head>"}]}',
            'html/assets/app.js' => "const marker = '</head>';\nexport default marker;\n",
        ];

        $this->publish(['html/index.html' => self::page()] + $files);

        foreach ($files as $path => $original) {
            $this->assertSame(
                $original,
                $this->stored($path),
                $path.' must be stored byte for byte as it was built',
            );
        }

        // And the HTML beside them was injected, so the skip is selective
        // rather than the injector not running at all.
        $this->assertStringContainsString(ChromeInjector::LOADER_PATH, $this->stored('html/index.html'));
    }

    /**
     * 🛑 Oversized is refused and **provably uncorrupted** (§8.15.4).
     *
     * The ceiling is `artifacts.chrome.max_html_bytes`. The document is built
     * just over it, so nothing about the assertion depends on the configured
     * value being any particular number.
     */
    public function test_an_oversized_document_is_refused_and_unchanged(): void
    {
        /*
         * 🛑 The ceiling is LOWERED for this test rather than the document being
         * grown past the shipped 4 MiB, and the reason is a real guard rather
         * than convenience: §8.3's ingest refuses an upload whose decompression
         * ratio is implausible, and four megabytes of one repeated character
         * trips it long before the injector sees the document. §8.15.4 says
         * "over the **configured** byte ceiling", so configuring it is testing
         * the requirement rather than working around it.
         */
        config(['artifacts.chrome.max_html_bytes' => 2048]);

        $padding = str_repeat('x', 2048);
        $oversized = '<!doctype html><html><head></head><body>'.$padding.'</body></html>';

        $this->publish(['html/index.html' => self::page(), 'html/big.html' => $oversized]);

        $this->assertSame($oversized, $this->stored('html/big.html'));
        $this->assertStringNotContainsString(ChromeInjector::LOADER_PATH, $this->stored('html/big.html'));

        // §8.15.3: recorded, with the outcome named.
        $coverage = $this->coverage();

        $this->assertSame(1, $coverage['outcomes'][InjectionOutcome::RefusedTooLarge->value] ?? 0);
    }

    /**
     * 🛑 Non-UTF-8 is refused rather than injected (§8.15.4), and unchanged.
     *
     * Not in §17's list and asserted anyway, because it is the one in §8.15.4
     * with a security argument rather than a cosmetic one: "a mis-declared
     * charset is an XSS vector", and inserting ASCII into a Shift-JIS document
     * produces bytes a browser guessing the encoding may read as something
     * else entirely.
     */
    public function test_a_non_utf8_document_is_refused_and_unchanged(): void
    {
        // Shift-JIS bytes that are not valid UTF-8, inside an otherwise ordinary
        // document — which is what a Japanese generator from 2012 emits.
        $shiftJis = "<!doctype html><html><head><title>\x93\xfa\x96\x7b\x8c\xea</title></head>"
            ."<body>\x82\xb1\x82\xf1\x82\xce\x82\xf1\x82\xcd</body></html>";

        $this->publish(['html/index.html' => self::page(), 'html/jp.html' => $shiftJis]);

        $this->assertSame($shiftJis, $this->stored('html/jp.html'));

        $coverage = $this->coverage();

        $this->assertSame(1, $coverage['outcomes'][InjectionOutcome::RefusedNonUtf8->value] ?? 0);
    }

    /**
     * 🛑 §8.15.10's gzip disposition, end to end.
     *
     * > "A pre-compressed HTML artifact MUST be decompressed, injected and
     * > recompressed at ingest, or refused with a stable error identifier. This
     * > is the **single** normative disposition for compressed HTML; no other
     * > requirement may state another, and nothing is rewritten on the serving
     * > path to compensate."
     *
     * So a gzipped document is **not** in the skip list — it is handled. What
     * "never corrupts" means here is that the sidecar is still valid gzip, still
     * decompresses to a well-formed document, and the document it decompresses
     * to carries the tags. A sidecar that decompressed to anything else would
     * hand a reader a broken page under a correct-looking 200, and §8.9.13
     * serves the sidecar by negotiation so most readers would get exactly that.
     */
    public function test_a_gzipped_document_is_decompressed_injected_and_recompressed(): void
    {
        $document = self::page();

        $this->publish([
            'html/index.html' => $document,
            'html/index.html.gz' => (string) gzencode($document, 9),
        ]);

        $sidecar = $this->stored('html/index.html.gz');

        $this->assertNotSame('', $sidecar, 'the sidecar is stored');

        $decompressed = gzdecode($sidecar);

        $this->assertIsString($decompressed, 'the stored sidecar is still valid gzip');
        $this->assertStringContainsString(ChromeInjector::LOADER_PATH, $decompressed);
        $this->assertStringContainsString('<meta name="docup" content="b=', $decompressed);

        // 🛑 And it decompresses to EXACTLY the injected document, not to
        // something merely similar: the plain file and the sidecar must be the
        // same bytes, or §8.9.12's two ETags describe two different documents.
        $this->assertSame($this->stored('html/index.html'), $decompressed);
    }

    /**
     * 🛑 A ranged response is never injected, proven through the real edge.
     *
     * §8.15.1 puts injection at **ingest**, so by construction nothing can
     * inject a response — ranged or otherwise. This asserts the construction
     * rather than the absence of code: the request goes through the real
     * resolver and the real handoff, and what comes back is a header naming a
     * file plus the `Range` the client asked for, with 🛑 **no body generated by
     * the application at all**.
     *
     * That is the whole of why §4.3/2's "documentation bytes never traverse PHP"
     * makes this exit criterion structural: PHP cannot corrupt a byte range it
     * never sees.
     */
    public function test_a_ranged_request_is_served_by_the_edge_with_no_body_from_php(): void
    {
        $this->publish(['html/index.html' => self::page(), 'html/assets/site.css' => str_repeat('a', 4096)]);

        $response = $this->getExactly(
            'http://'.$this->host.'/en/latest/assets/site.css',
            ['Range' => 'bytes=0-15'],
        );

        $response->assertOk();

        // The application named a file and sent nothing.
        $this->assertSame('', (string) $response->getContent());
        $this->assertNotSame('', (string) $response->headers->get('X-Accel-Redirect'));

        /*
         * 🛑 And the application did not answer the Range itself. §8.9.8's
         * whole argument is that the handoff "buys ETags, If-None-Match and
         * Range from the web server" — a 206 from PHP here would mean PHP had
         * read the file, which is the architecture quietly becoming something
         * else.
         */
        $this->assertSame(200, $response->getStatusCode());
        $this->assertFalse($response->headers->has('Content-Range'));
    }

    /**
     * 🛑 §8.15.3's warning excludes navigational stubs, and the stubs are still
     * recorded.
     *
     * ADR 0002's finding, asserted on both sides: "every Antora site warns on
     * every build forever and operators learn to ignore injection warnings".
     */
    public function test_a_navigational_stub_is_recorded_and_does_not_warn(): void
    {
        $this->publish([
            'html/index.html' => self::page(),
            /*
             * 🛑 What Antora emits at a site root, and the shape matters: §8.15.3
             * defines a stub as "a document with **no `<head>` element** whose
             * body is only a meta-refresh or a `location=` assignment". A
             * redirect that DOES carry a head is injected like any other
             * document, which is correct — the exemption is for documents the
             * injector cannot reach, not for documents that redirect.
             */
            'html/redirect.html' => '<html><body><script>location.replace("en/latest/")</script></body></html>',
        ]);

        $coverage = $this->coverage();

        $this->assertSame(1, $coverage['outcomes'][InjectionOutcome::SkippedStub->value] ?? 0);
        $this->assertNotSame([], $coverage['stub_samples'], 'the stub stays in the record');

        // 🛑 And the warning is silent about it.
        $health = app(ChromeHealth::class)->forProject($this->freshProject());

        $this->assertNull($health['warning'], 'a stub must not raise a warning');
        $this->assertSame('injected', $health['mode_applied'], 'nor force the api_only fallback');
    }

    /**
     * 🛑 §8.15.4's per-project warning, surfaced and naming the files.
     *
     * Also the §8.15.4 fallback: the project asked for `injected` and gets
     * `api_only` applied, because one document in the artifact has no `</head>`
     * at all.
     */
    public function test_an_uninjectable_artifact_warns_per_project_and_falls_back(): void
    {
        $this->publish([
            'html/index.html' => self::page(),
            // A real page with real prose and no head element — not a stub.
            'html/headless.html' => '<html><body><h1>Release notes</h1>'
                .'<p>This page documents the behaviour of the export job and the '
                .'retention window that applies to it.</p></body></html>',
        ]);

        $health = app(ChromeHealth::class)->forProject($this->freshProject());

        $this->assertNotNull($health['warning'], '§8.15.4 requires the skip to be surfaced');
        $this->assertSame(
            ['html/headless.html'],
            $health['warning']['versions']['en/latest']['files'],
            'the warning names the affected files',
        );

        // 🛑 The fallback, per §8.15.4.
        $this->assertSame('injected', $health['mode'], 'the project still asks for injected');
        $this->assertSame('api_only', $health['mode_applied'], 'and the build serves api_only');

        // And the payload tells the runtime, so it renders nothing.
        $this->assertSame('api_only', $this->addonsMode());
    }

    /**
     * 🛑 §8.15.4's re-ingest job: the stamp, and the job acting on it.
     *
     * The stamp is forced backwards to simulate an upgrade that changed
     * {@see ChromeInjector::VERSION} — which is the only way to test this
     * without a second injector version existing, and is honest about being a
     * simulation. What is real is everything after: the job finds the version,
     * re-publishes from the **stored bytes** with no repository involved, and
     * the new artifact carries the current tags under a new build id.
     */
    public function test_the_reingest_job_republishes_a_stale_artifact_from_stored_bytes(): void
    {
        $this->publish(['html/index.html' => self::page(), 'html/guide.html' => self::page()]);

        $original = $this->stored('html/index.html');
        $oldBuildId = $this->buildId();

        DB::table('builds')
            ->where('id', Uuid::toBytes($oldBuildId))
            ->update(['injector_version' => ChromeInjector::VERSION - 1]);

        Cache::flush();

        /** @var ChromeReingest $reingest */
        $reingest = app(ChromeReingest::class);

        $stale = $reingest->stale();

        $this->assertCount(1, $stale, 'the stale version is found by its stamp');
        $this->assertSame($this->version->id, $stale[0]->id);

        $newBuildId = $reingest->reingest($stale[0], $this->fixtures);

        $this->assertIsString($newBuildId);
        $this->assertNotSame($oldBuildId, $newBuildId, 'a re-ingest is a new build, never a rewrite');

        // 🛑 The old artifact is untouched. §8.8.1's write-once is what makes
        // §8.5.24's provenance mean anything.
        $this->assertSame($original, $this->storedIn($oldBuildId, 'html/index.html'));

        // The new one carries the current tags and the current stamp.
        $this->assertStringContainsString(
            ChromeInjector::LOADER_PATH,
            $this->storedIn($newBuildId, 'html/index.html'),
        );

        $newBuild = Build::withoutGlobalScopes()->whereKey(Uuid::toBytes($newBuildId))->firstOrFail();

        $this->assertSame(ChromeInjector::VERSION, $newBuild->injector_version);

        // And the version now points at it, so a reader gets the re-ingested
        // bytes with no further action.
        $this->assertSame($newBuildId, $this->buildId());

        // Nothing is stale any more.
        Cache::flush();
        $this->assertSame([], $reingest->stale());

        // 🛑 The intermediate archive is not left behind. A complete copy of a
        // published tree in a work directory is a disclosure waiting for
        // somebody to serve the directory.
        $this->assertSame(
            [],
            array_values(array_filter(
                (array) glob($this->fixtures.'/reingest-*'),
                static fn (mixed $path): bool => is_string($path),
            )),
        );
    }

    /** §8.15.3's build warning, on the build the API serves. */
    public function test_the_build_endpoint_reports_the_injection_coverage(): void
    {
        $this->publish([
            'html/index.html' => self::page(),
            'html/headless.html' => '<html><body><p>'.str_repeat('prose ', 20).'</p></body></html>',
        ]);

        $build = Build::withoutGlobalScopes()
            ->where('project_version_id', $this->version->id)
            ->firstOrFail();

        $report = app(ChromeHealth::class)->forBuild($build);

        $this->assertSame(2, $report['documents']);
        $this->assertSame(1, $report['injected']);
        $this->assertSame(50.0, $report['percentage']);
        $this->assertSame(ChromeInjector::VERSION, $report['injector_version']);
        $this->assertFalse($report['stale']);
        $this->assertSame('api_only', $report['mode_applied']);
        $this->assertNotNull($report['warning']);
        $this->assertSame(['html/headless.html'], $report['warning']['files']);
    }

    // ------------------------------------------------------------- helpers

    /**
     * The project row, read without the tenant scope.
     *
     * 🛑 `$project->refresh()` would be a §8.2.1-scoped query, and the test body
     * runs with no context declared — the publish helper declares one and
     * restores it, exactly as a request does. Found by the global scope
     * refusing, which is it doing its job on a test.
     */
    private function freshProject(): Project
    {
        return Project::withoutGlobalScopes()->whereKey($this->project->id)->firstOrFail();
    }

    /** A small, valid PNG — encoded by GD, never hand-written. */
    private static function png(): string
    {
        /*
         * 🛑 GD-encoded, and Phase 27's build log records why in detail: a
         * hand-written image fixture crashed CI's libgd with a SIGSEGV while
         * passing locally, and it was hiding a real bug in the re-encoder. The
         * rule that came out of it is that every fixture which gets decoded is
         * a GD-encoded image.
         */
        $image = imagecreatetruecolor(2, 2);

        if ($image === false) {
            return '';
        }

        ob_start();
        imagepng($image);
        $bytes = (string) ob_get_clean();
        imagedestroy($image);

        return $bytes;
    }

    /** A page with a lower-case `</head>` and no whitespace, as generators emit. */
    private static function page(): string
    {
        return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            .'<title>Guide</title></head><body><h1>Guide</h1></body></html>';
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

        return TestResponse::fromBaseResponse($this->app->handle($request));
    }

    private function addonsMode(): string
    {
        $response = $this->getExactly(
            'http://'.$this->host.'/_/addons?path='.urlencode('/en/latest/'),
        );

        $response->assertOk();

        /** @var array<string, mixed> $payload */
        $payload = json_decode((string) $response->getContent(), true, 64, JSON_THROW_ON_ERROR);

        return (string) $payload['chrome_mode'];
    }

    /** @param array<string, string> $files */
    private function publish(array $files): void
    {
        $writer = new ArchiveWriter;

        foreach ($files as $path => $contents) {
            $writer->add($path, $contents);
        }

        $archive = $writer->toTarGz($this->fixtures.'/tree-'.bin2hex(random_bytes(3)).'.tar.gz');

        $this->context->for($this->organisation->id);

        /** @var Publisher $publisher */
        $publisher = app(Publisher::class);
        $publisher->publishUpload($this->version, $archive);
        $this->version->refresh();

        $this->context->forget();
    }

    /**
     * The build the version currently **publishes**.
     *
     * 🛑 Resolved through `published_manifest_id`, not as "the newest `builds`
     * row". Two builds created in the same millisecond tie on `created_at`, so
     * ordering by it returned the pre-re-ingest build and the pointer assertion
     * passed for the wrong reason — found by the re-ingest test, where two
     * builds of one version exist for the first time.
     *
     * The manifest IS the pointer (§8.8.3), so reading it is the claim rather
     * than a convenient proxy for it.
     */
    private function buildId(): string
    {

        $json = DB::table('project_version_manifests')
            ->where('id', $this->publishedManifestId())
            ->value('mounts_json');

        $decoded = is_string($json) ? json_decode($json, true) : null;
        $mounts = is_array($decoded) && is_array($decoded['mounts'] ?? null) ? $decoded['mounts'] : [];

        foreach ($mounts as $mount) {
            if (is_array($mount) && ($mount['is_primary'] ?? false) === true && is_string($mount['build_id'] ?? null)) {
                return $mount['build_id'];
            }
        }

        $this->fail('the version publishes no primary build');
    }

    /** The version's published manifest id, read without the tenant scope. */
    private function publishedManifestId(): string
    {
        $id = ProjectVersion::withoutGlobalScopes()
            ->whereKey($this->version->id)
            ->value('published_manifest_id');

        $this->assertIsString($id, 'the version has a published manifest');

        return $id;
    }

    private function stored(string $path): string
    {
        return $this->storedIn($this->buildId(), $path);
    }

    private function storedIn(string $buildId, string $path): string
    {
        $key = 'builds/'.$buildId.'/'.$path;

        $this->assertTrue(Storage::disk('artifacts')->exists($key), $key.' is stored');

        return (string) Storage::disk('artifacts')->get($key);
    }

    /**
     * §8.15.3's stored coverage record for the latest build.
     *
     * @return array{outcomes: array<string, int>, stub_samples: list<string>, warning_samples: list<string>}
     */
    private function coverage(): array
    {
        $build = Build::withoutGlobalScopes()
            ->where('project_version_id', $this->version->id)
            ->orderByDesc('created_at')
            ->firstOrFail();

        /** @var array{outcomes: array<string, int>, stub_samples: list<string>, warning_samples: list<string>} $coverage */
        $coverage = is_array($build->chrome_coverage) ? $build->chrome_coverage : [];

        return $coverage;
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
