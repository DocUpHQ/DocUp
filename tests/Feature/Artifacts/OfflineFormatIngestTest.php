<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Artifacts;

use App\Artifacts\ArtifactIngestor;
use App\Artifacts\ChromeInjector;
use App\Artifacts\Exceptions\IngestRejected;
use App\Artifacts\IngestCaps;
use App\Artifacts\IngestResult;
use App\Artifacts\LocalArtifactStore;
use App\Artifacts\RejectionCode;
use App\Serving\OfflineFormat;
use App\Support\Uuid;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Feature\Serving\DownloadServingTest;
use Tests\Support\ArchiveWriter;
use Tests\TestCase;

/**
 * 🛑 §8.4.5's offline-format half of the output contract, and two of Phase
 * 12's exit criteria.
 *
 * > "each offline format directory MUST contain exactly one file. 🛑 It MUST
 * > be stored under an identifier-free leaf name, with the
 * > `<project>-<version>.<ext>` download filename applied at serve time by
 * > `Content-Disposition` and **never** written into the storage key."
 *
 * The serve-time half is {@see DownloadServingTest};
 * this file is the store-time half — what the object is called and where it
 * is, which is the part a rename must not be able to reach.
 */
final class OfflineFormatIngestTest extends TestCase
{
    private string $fixtures;

    private LocalArtifactStore $store;

    private ArtifactIngestor $ingestor;

    private string $buildId;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');

        $this->fixtures = sys_get_temp_dir().'/docup-offline-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->store = new LocalArtifactStore('artifacts');
        $this->ingestor = new ArtifactIngestor($this->store, IngestCaps::fromConfig(), ChromeInjector::fromConfig());
        $this->buildId = Uuid::v7();
    }

    protected function tearDown(): void
    {
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
     * 🛑 Phase 12's exit criterion: "the stored object path provably contains
     * no slug".
     *
     * The archive names each file the way a real generator does — Sphinx
     * takes the PDF's name from `project` in `conf.py`, which is the author's
     * own string and exactly what §8.8.1 forbids in a storage key. Ingest
     * renames it, so the slug never reaches the store at all rather than
     * being stripped later by something that might be skipped.
     */
    public function test_an_offline_format_is_stored_under_an_identifier_free_leaf(): void
    {
        $result = $this->ingest([
            'html/index.html' => '<html><body>docs</body></html>',
            'pdf/My Great Project.pdf' => '%PDF-1.7 fake',
            'epub/my-great-project.epub' => 'PK fake epub',
            'htmlzip/my-great-project.zip' => 'PK fake zip',
        ]);

        $paths = array_keys($result->manifest->toArray()['files']);

        $this->assertContains('pdf/document.pdf', $paths);
        $this->assertContains('epub/document.epub', $paths);
        $this->assertContains('htmlzip/document.zip', $paths);

        foreach ($paths as $path) {
            $this->assertStringNotContainsStringIgnoringCase(
                'great',
                $path,
                '🛑 §8.8.1: no project slug, version slug, language or user-supplied name in any storage key',
            );
        }

        // And the bytes really are at the canonical key, not merely named
        // there in the manifest.
        $prefix = $this->store->prefixFor($this->buildId);

        $this->assertTrue(Storage::disk('artifacts')->exists($prefix.'/pdf/document.pdf'));
        $this->assertFalse(Storage::disk('artifacts')->exists($prefix.'/pdf/My Great Project.pdf'));
    }

    /**
     * 🛑 `htmlzip` stores `.zip`, because the directory names the format and
     * the extension names the media type.
     *
     * `document.htmlzip` is a file no operating system knows how to open,
     * and §8.9.11's allowlist has no such extension — so it would be served
     * as an unknown type, which is the one case the allowlist exists to
     * answer badly on purpose.
     */
    public function test_htmlzip_is_stored_with_a_zip_extension(): void
    {
        $this->assertSame('htmlzip/document.zip', ArtifactIngestor::offlineLeafFor('htmlzip'));
        $this->assertSame('pdf/document.pdf', ArtifactIngestor::offlineLeafFor('pdf'));
        $this->assertSame('epub/document.epub', ArtifactIngestor::offlineLeafFor('epub'));
    }

    /**
     * 🛑 The ingest side and the serving side must agree on the path, and
     * they derive it separately.
     *
     * A shared constant would be one edit away from a download that 404s
     * because ingest renamed the file and serving did not — the two are in
     * different namespaces and are written by different phases, so the
     * agreement is asserted rather than assumed.
     */
    public function test_the_ingest_leaf_and_the_serving_path_agree(): void
    {
        foreach (OfflineFormat::cases() as $format) {
            $this->assertSame(
                ArtifactIngestor::offlineLeafFor($format->value),
                $format->manifestPath(),
                $format->value.': ingest stores one path and serving reads another',
            );
        }
    }

    /**
     * 🛑 The extension comes from the FORMAT, never from the uploaded name.
     *
     * `pdf/payload.html` is the "HTML file renamed `.pdf`" case arriving from
     * the other direction — a build writing an HTML file into the pdf
     * directory. Stored as `pdf/document.pdf`, its content type is decided by
     * the directory the build chose rather than by a name the build wrote,
     * and {@see DownloadServingTest} then refuses to
     * render it whatever its bytes say.
     */
    public function test_an_html_file_in_the_pdf_directory_is_stored_as_a_pdf_leaf(): void
    {
        $result = $this->ingest([
            'html/index.html' => '<html><body>docs</body></html>',
            'pdf/payload.html' => '<html><script>alert(1)</script></html>',
        ]);

        $paths = array_keys($result->manifest->toArray()['files']);

        $this->assertContains('pdf/document.pdf', $paths);
        $this->assertNotContains('pdf/payload.html', $paths);
        $this->assertNotContains('pdf/document.html', $paths);
    }

    /**
     * 🛑 Phase 12's exit criterion: "A two-file `pdf/` directory fails ingest
     * with a stable identifier."
     *
     * Rejected rather than resolved: picking one of the two would publish a
     * download whose contents depend on archive ordering, and an author who
     * wrote two PDFs has a configuration problem a green build would hide.
     *
     * @param  array<string, string>  $files
     */
    #[DataProvider('twoFileDirectories')]
    public function test_two_files_in_one_offline_directory_are_refused(
        array $files,
        RejectionCode $expected,
    ): void {
        try {
            $this->ingest(['html/index.html' => '<html></html>'] + $files);
            $this->fail('a second file in an offline format directory must be refused');
        } catch (IngestRejected $rejected) {
            $this->assertSame($expected, $rejected->rejection);
            $this->assertStringStartsWith('contract.', $expected->value, '§8.1.11: a stable identifier');
        }
    }

    /** @return array<string, array{0: array<string, string>, 1: RejectionCode}> */
    public static function twoFileDirectories(): array
    {
        return [
            'pdf' => [
                ['pdf/one.pdf' => 'a', 'pdf/two.pdf' => 'b'],
                RejectionCode::MultiplePdfFiles,
            ],
            'epub' => [
                ['epub/one.epub' => 'a', 'epub/two.epub' => 'b'],
                RejectionCode::MultipleEpubFiles,
            ],
            'htmlzip' => [
                ['htmlzip/one.zip' => 'a', 'htmlzip/two.zip' => 'b'],
                RejectionCode::MultipleHtmlzipFiles,
            ],
        ];
    }

    /**
     * 🛑 Refused BEFORE anything is written.
     *
     * §8.8.2 puts the whole validation pass before the first byte reaches the
     * store, and the two-file case is the one where a half-written build is
     * most tempting: the first file is valid on its own. A store holding one
     * of the two PDFs would be an artifact nothing can ever publish and
     * nothing will ever collect, because no build row references it.
     */
    public function test_a_refused_tree_writes_nothing(): void
    {
        try {
            $this->ingest([
                'html/index.html' => '<html></html>',
                'pdf/one.pdf' => 'a',
                'pdf/two.pdf' => 'b',
            ]);
        } catch (IngestRejected) {
            // expected
        }

        $this->assertSame(
            [],
            Storage::disk('artifacts')->allFiles($this->store->prefixFor($this->buildId)),
            'a rejected ingest must leave the store untouched',
        );
    }

    /** One offline file is the normal case and is accepted. */
    public function test_one_file_per_directory_is_accepted(): void
    {
        $result = $this->ingest([
            'html/index.html' => '<html><body>d</body></html>',
            'pdf/doc.pdf' => '%PDF-1.7',
        ]);

        $formats = array_map(
            static fn (object $output): string => $output->format,
            $result->outputs,
        );

        $this->assertContains('pdf', $formats);
        $this->assertContains('html', $formats);
    }

    /**
     * An html tree with no offline formats is unaffected — the overwhelming
     * majority of builds, and the one this must not have broken.
     */
    public function test_a_build_with_no_offline_formats_is_unchanged(): void
    {
        $result = $this->ingest([
            'html/index.html' => '<html><body>d</body></html>',
            'html/guide/index.html' => '<html><body>g</body></html>',
            'html/assets/app.css' => 'body{}',
        ]);

        $paths = array_keys($result->manifest->toArray()['files']);

        sort($paths);

        $this->assertSame(
            ['html/assets/app.css', 'html/guide/index.html', 'html/index.html'],
            $paths,
            'html paths are never rewritten: the tree is served path-for-path',
        );
    }

    /**
     * @param  array<string, string>  $files
     */
    private function ingest(array $files): IngestResult
    {
        $members = [];

        foreach ($files as $name => $contents) {
            $members[$name] = [$contents, 0o644];
        }

        return $this->ingestor->ingest(
            $this->buildId,
            ArchiveWriter::zip($this->fixtures.'/offline.zip', $members),
        );
    }
}
