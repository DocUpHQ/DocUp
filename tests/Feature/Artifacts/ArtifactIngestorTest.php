<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Artifacts;

use App\Artifacts\ArtifactIngestor;
use App\Artifacts\Exceptions\ArtifactWriteRefused;
use App\Artifacts\Exceptions\IngestRejected;
use App\Artifacts\FileManifest;
use App\Artifacts\IngestCaps;
use App\Artifacts\LocalArtifactStore;
use App\Support\Uuid;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\ArchiveWriter;
use Tests\Support\HostileArchives;
use Tests\TestCase;

/**
 * §8.8.2 — the single `ArtifactIngestor`.
 *
 * 🛑 The hostile cases are driven from `tests/Fixtures/AbuseCorpus/corpus.json`,
 * not from a list in this file. That is the whole point of the corpus (§9.4):
 * Phase 00 committed the expected identifier for each attack **before** any of
 * this code existed, so the implementation is measured against a prior
 * commitment rather than against itself. A list here would be a list the
 * implementation could quietly be edited to agree with.
 *
 * No database: nothing here touches a row, and `RefreshDatabase` on a suite this
 * size would be most of its runtime. §9.4 wants the abuse corpus fast enough to
 * run on every push.
 */
final class ArtifactIngestorTest extends TestCase
{
    private string $fixtures;

    private LocalArtifactStore $store;

    private IngestCaps $caps;

    private ArtifactIngestor $ingestor;

    private string $buildId;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');

        $this->fixtures = sys_get_temp_dir().'/docup-corpus-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->store = new LocalArtifactStore('artifacts');
        $this->caps = IngestCaps::fromConfig();
        $this->ingestor = new ArtifactIngestor($this->store, $this->caps);
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
     * Every `archive` case in the corpus, keyed so a failure names the attack.
     *
     * @return \Generator<string, array{0: array<string, string>}>
     */
    public static function hostileArchives(): \Generator
    {
        /** @var array{cases: list<array<string, string>>} $corpus */
        $corpus = json_decode(
            (string) file_get_contents(__DIR__.'/../../Fixtures/AbuseCorpus/corpus.json'),
            true,
            64,
            JSON_THROW_ON_ERROR,
        );

        foreach ($corpus['cases'] as $case) {
            if (($case['category'] ?? null) !== 'archive') {
                continue;
            }

            yield $case['id'].' '.($case['builder'] ?? '?') => [$case];
        }
    }

    /** @param  array<string, string>  $case */
    #[DataProvider('hostileArchives')]
    public function test_a_hostile_archive_is_refused_with_the_committed_identifier(array $case): void
    {
        /*
         * A corpus case with no builder has no fixture, so it silently stops
         * running while the suite still reports green — the one failure mode the
         * corpus exists to prevent. HostileArchives::build() says so by name.
         */
        $this->assertArrayHasKey('builder', $case, "Corpus case {$case['id']} names no builder.");

        $archive = HostileArchives::build($case['builder'], $this->fixtures);

        try {
            $this->ingestor->ingest($this->buildId, $archive);
        } catch (IngestRejected $rejection) {
            $this->assertSame(
                $case['expect'],
                $rejection->rejection->value,
                "Corpus case {$case['id']} (defends §{$case['defends']}) expected {$case['expect']}.",
            );

            $this->assertSame('contract', $rejection->rejection->failureClass());

            /*
             * 🛑 Nothing may be written before a tree is refused. §8.8.2's named
             * example is `.user.ini` — "code execution if the storage root is
             * ever a PHP document root" — so the window between writing it and
             * deleting it again is the entire attack, and there must be no
             * window. This assertion is what found an earlier version that
             * wrote each file as it hashed it.
             */
            $this->assertSame([], Storage::disk('artifacts')->allFiles());

            return;
        }

        $this->fail(
            "Corpus case {$case['id']} ({$case['builder']}) was accepted. "
            ."It must be refused with {$case['expect']}."
        );
    }

    public function test_it_publishes_a_three_file_tree_with_a_per_file_sha256(): void
    {
        $archive = HostileArchives::build('valid_three_file_tree', $this->fixtures);

        $result = $this->ingestor->ingest($this->buildId, $archive);

        $this->assertSame(3, $result->fileCount);
        $this->assertSame([
            'html/assets/site.css',
            'html/guide.html',
            'html/index.html',
        ], $result->manifest->paths());

        // The exit criterion: a per-file sha256, and one that is the digest of
        // the bytes actually stored rather than of what the archive claimed.
        foreach ($result->manifest->paths() as $path) {
            $entry = $result->manifest->get($path);
            $stored = (string) Storage::disk('artifacts')
                ->get('builds/'.Uuid::toText($this->buildId).'/'.$path);

            $this->assertNotNull($entry);
            $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $entry['sha256']);
            $this->assertSame(hash('sha256', $stored), $entry['sha256'], $path);
            $this->assertSame(strlen($stored), $entry['bytes'], $path);
        }

        $index = $result->manifest->get('html/index.html');
        $css = $result->manifest->get('html/assets/site.css');

        $this->assertNotNull($index);
        $this->assertNotNull($css);
        $this->assertSame('text/html; charset=utf-8', $index['content_type']);
        $this->assertSame('text/css; charset=utf-8', $css['content_type']);
    }

    public function test_every_object_is_keyed_by_build_id_alone(): void
    {
        $archive = HostileArchives::build('valid_three_file_tree', $this->fixtures);

        $this->ingestor->ingest($this->buildId, $archive);

        $prefix = 'builds/'.Uuid::toText($this->buildId).'/';

        // 🛑 §8.8.1: "No project slug, version slug, language or user-supplied
        // name MUST appear in any storage key, so renaming can never strand or
        // invalidate stored artifacts."
        foreach (Storage::disk('artifacts')->allFiles() as $key) {
            $this->assertStringStartsWith($prefix, $key);
        }
    }

    public function test_the_manifest_is_stored_outside_every_served_tree(): void
    {
        $archive = HostileArchives::build('valid_three_file_tree', $this->fixtures);

        $result = $this->ingestor->ingest($this->buildId, $archive);

        /*
         * 🛑 At builds/{id}/html/manifest.json the manifest would be a public
         * URL on the documentation origin, handing any visitor the sha256 and
         * size of every file in the tree — including files behind §12's access
         * rules.
         */
        $this->assertSame(
            'builds/'.Uuid::toText($this->buildId).'/manifest/manifest.json',
            $result->manifestKey,
        );

        foreach ($result->manifest->paths() as $path) {
            $this->assertStringStartsNotWith('manifest/', $path);
        }

        $stored = (string) Storage::disk('artifacts')->get($result->manifestKey);

        $this->assertSame($result->contentSha256, FileManifest::decode($stored)->digest());
    }

    public function test_a_zip_and_a_tar_of_one_tree_produce_identical_manifests(): void
    {
        $tar = HostileArchives::build('valid_three_file_tree', $this->fixtures);
        $zip = HostileArchives::build('valid_zip_tree', $this->fixtures);

        $fromTar = $this->ingestor->ingest(Uuid::v7(), $tar);
        $fromZip = $this->ingestor->ingest(Uuid::v7(), $zip);

        // 🛑 Two readers, one answer. If the formats disagreed about what a tree
        // contains, §8.7.9's content key would depend on how a runner chose to
        // pack its output, and two identical builds would look different.
        $this->assertSame($fromTar->manifest->encode(), $fromZip->manifest->encode());
        $this->assertSame($fromTar->contentSha256, $fromZip->contentSha256);
        $this->assertSame('tar.gz', $fromTar->archiveFormat);
        $this->assertSame('zip', $fromZip->archiveFormat);
    }

    public function test_it_accepts_the_tree_as_tar_c_dir_dot_emits_it(): void
    {
        $archive = HostileArchives::build('dot_prefixed_tree', $this->fixtures);

        $result = $this->ingestor->ingest($this->buildId, $archive);

        // One leading './' is stripped: removing it cannot change which file a
        // path names, and refusing it would fail the most natural packing
        // command for no defensive gain.
        $this->assertSame(['html/guide.html', 'html/index.html'], $result->manifest->paths());
    }

    public function test_it_refuses_a_ratio_above_the_cap_and_accepts_one_below_it(): void
    {
        // 1 MiB of a repeating pattern, which gzip reduces enough that a cap can
        // be aimed either side of the real ratio.
        $payload = str_repeat('docup', 209_716);

        $archive = (new ArchiveWriter)
            ->add('html/index.html', "<!doctype html><p>ok</p>\n")
            ->add('html/big.txt', $payload)
            ->toTarGz($this->fixtures.'/ratio.tar.gz');

        /*
         * Measured against the DECOMPRESSED STREAM, not the sum of the member
         * sizes. The two differ — headers, per-member padding and the terminator
         * are stream bytes belonging to no member — and the stream figure is the
         * binding one, because TarArchiveReader::materialise() stops
         * decompressing at the ceiling and never reaches a header. An earlier
         * version of this test computed the member total, set a cap just above
         * it, and was still refused: the cap it chose was below the real
         * expansion.
         */
        $streamBytes = strlen((string) gzdecode((string) file_get_contents($archive)));
        $ratio = $streamBytes / (int) filesize($archive);

        // Either side of the real ratio. Testing the boundary rather than a
        // 1000:1 bomb is what proves the comparison is the right way round — a
        // reversed `>` would still refuse an obvious bomb and look correct.
        $strict = new ArtifactIngestor($this->store, $this->caps->with(compressionRatio: $ratio - 1.0));
        $lenient = new ArtifactIngestor($this->store, $this->caps->with(compressionRatio: $ratio + 1.0));

        try {
            $strict->ingest(Uuid::v7(), $archive);
            $this->fail('An archive expanding past the cap was accepted.');
        } catch (IngestRejected $rejection) {
            $this->assertSame('contract.compression_ratio_exceeded', $rejection->rejection->value);
        }

        $this->assertSame(2, $lenient->ingest(Uuid::v7(), $archive)->fileCount);
    }

    public function test_it_refuses_to_overwrite_a_stored_object(): void
    {
        $archive = HostileArchives::build('valid_three_file_tree', $this->fixtures);

        $this->ingestor->ingest($this->buildId, $archive);

        // 🛑 §8.8.5 needs the previous build intact for rollback to mean
        // anything, so a key is written once. Re-ingesting the same build id is
        // the cheapest way to prove the store refuses rather than replaces.
        $this->expectException(ArtifactWriteRefused::class);

        $this->ingestor->ingest($this->buildId, $archive);
    }

    public function test_it_records_a_per_format_output_for_each_format_directory(): void
    {
        $archive = (new ArchiveWriter)
            ->add('html/index.html', "<!doctype html><p>ok</p>\n")
            ->add('html/guide.html', "<p>guide</p>\n")
            ->add('pdf/docs.pdf', "%PDF-1.7\n")
            ->toTarGz($this->fixtures.'/multi.tar.gz');

        $result = $this->ingestor->ingest($this->buildId, $archive);

        $html = $result->output('html');
        $pdf = $result->output('pdf');

        $this->assertSame(['html', 'pdf'], $result->formats());
        $this->assertNotNull($html);
        $this->assertNotNull($pdf);
        $this->assertSame(2, $html->fileCount);
        $this->assertSame(1, $pdf->fileCount);
        $this->assertSame('builds/'.Uuid::toText($this->buildId).'/pdf', $pdf->storageKey);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $html->contentSha256);
        $this->assertSame($result->manifest->totalBytes(), $result->totalBytes);
    }

    public function test_it_refuses_a_file_over_the_per_file_cap(): void
    {
        $archive = (new ArchiveWriter)
            ->add('html/index.html', "<!doctype html><p>ok</p>\n")
            ->add('html/big.bin', str_repeat('x', 4096))
            ->toTar($this->fixtures.'/perfile.tar');

        $ingestor = new ArtifactIngestor($this->store, $this->caps->with(fileBytes: 1024));

        try {
            $ingestor->ingest($this->buildId, $archive);
            $this->fail('A file over the per-file cap was accepted.');
        } catch (IngestRejected $rejection) {
            $this->assertSame('contract.file_size_exceeded', $rejection->rejection->value);
        }
    }

    public function test_it_refuses_a_tree_over_the_total_size_cap(): void
    {
        $archive = (new ArchiveWriter)
            ->add('html/index.html', str_repeat('x', 1024))
            ->add('html/a.txt', str_repeat('x', 1024))
            ->add('html/b.txt', str_repeat('x', 1024))
            ->toTar($this->fixtures.'/total.tar');

        $ingestor = new ArtifactIngestor($this->store, $this->caps->with(totalBytes: 2048));

        try {
            $ingestor->ingest($this->buildId, $archive);
            $this->fail('A tree over the total-size cap was accepted.');
        } catch (IngestRejected $rejection) {
            $this->assertSame('contract.total_size_exceeded', $rejection->rejection->value);
        }
    }

    public function test_it_escapes_an_attacker_supplied_entry_name_in_the_message(): void
    {
        $archive = (new ArchiveWriter)
            ->add('html/index.html', "<!doctype html><p>ok</p>\n")
            ->add("html/x\n2026-01-01 INFO nothing to see.php", 'x')
            ->toTar($this->fixtures.'/forged.tar');

        try {
            $this->ingestor->ingest($this->buildId, $archive);
            $this->fail('The forged entry name was accepted.');
        } catch (IngestRejected $rejection) {
            /*
             * 🛑 An entry name reaches the build log and the API response. One
             * carrying a newline must not be able to forge a log record, so the
             * message may contain an escape sequence but never the raw control
             * character.
             */
            $this->assertStringNotContainsString("\n", $rejection->getMessage());
            $this->assertStringContainsString('\\n', $rejection->getMessage());
        }
    }
}
