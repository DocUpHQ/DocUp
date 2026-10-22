<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Artifacts\ArtifactIngestor;
use App\Artifacts\Exceptions\ArtifactWriteRefused;
use App\Artifacts\Exceptions\IngestRejected;
use App\Artifacts\FileManifest;
use App\Artifacts\IngestCaps;
use App\Artifacts\LocalArtifactStore;
use App\Support\Uuid;
use Illuminate\Support\Facades\Storage;
use Tests\Support\ArchiveWriter;
use Tests\Support\HostileArchives;

/*
|------------------------------------------------------------------------------
| §8.8.2 — the single ArtifactIngestor
|------------------------------------------------------------------------------
| 🛑 The hostile cases are driven from tests/Fixtures/AbuseCorpus/corpus.json,
| not from a list in this file. That is the whole point of the corpus (§9.4):
| Phase 00 committed the expected identifier for each attack BEFORE any code
| existed, so the implementation is measured against a prior commitment rather
| than against whatever it happens to do. A list here would be a list the
| implementation could be quietly edited to agree with.
*/

beforeEach(function (): void {
    Storage::fake('artifacts');

    $this->fixtures = sys_get_temp_dir().'/docup-corpus-'.getmypid();

    if (! is_dir($this->fixtures)) {
        mkdir($this->fixtures, 0o755, true);
    }

    $this->store = new LocalArtifactStore('artifacts');
    $this->caps = IngestCaps::fromConfig();
    $this->ingestor = new ArtifactIngestor($this->store, $this->caps);
    $this->buildId = Uuid::v7();
});

afterEach(function (): void {
    if (is_dir($this->fixtures)) {
        foreach ((array) glob($this->fixtures.'/*') as $file) {
            if (is_string($file)) {
                @unlink($file);
            }
        }

        @rmdir($this->fixtures);
    }
});

dataset('hostileArchives', function (): Generator {
    /** @var array{cases: list<array{id: string, category: string, builder?: string, expect: string, defends: string}>} $corpus */
    $corpus = json_decode(
        (string) file_get_contents(__DIR__.'/../../Fixtures/AbuseCorpus/corpus.json'),
        true,
        64,
        JSON_THROW_ON_ERROR,
    );

    foreach ($corpus['cases'] as $case) {
        if ($case['category'] !== 'archive') {
            continue;
        }

        // Keyed by id and builder so a failure names the attack, not "dataset #7".
        yield $case['id'].' '.($case['builder'] ?? '?') => [$case];
    }
});

it('refuses a hostile archive with the identifier the corpus commits to', function (array $case): void {
    // A corpus case with no builder has no fixture, so it silently stops
    // running while the suite still reports green - the one failure mode the
    // corpus exists to prevent. HostileArchives::build() says so by name.
    expect($case['builder'] ?? null)->toBeString();

    $archive = HostileArchives::build((string) $case['builder'], $this->fixtures);

    try {
        $this->ingestor->ingest($this->buildId, $archive);
    } catch (IngestRejected $rejection) {
        expect($rejection->rejection->value)->toBe(
            $case['expect'],
            "Corpus case {$case['id']} (defends §{$case['defends']}) expected {$case['expect']}.",
        );

        expect($rejection->rejection->failureClass())->toBe('contract');

        // 🛑 Nothing may be written before a tree is refused. §8.8.2's named
        // example is `.user.ini`, which is "code execution if the storage root
        // is ever a PHP document root" — so the window between writing it and
        // deleting it again is the entire attack, and there must be no window.
        expect(Storage::disk('artifacts')->allFiles())->toBe([]);

        return;
    }

    $this->fail("Corpus case {$case['id']} ({$case['builder']}) was accepted. It must be refused with {$case['expect']}.");
})->with('hostileArchives');

it('publishes a three-file tree and lists a per-file sha256', function (): void {
    $archive = HostileArchives::build('valid_three_file_tree', $this->fixtures);

    $result = $this->ingestor->ingest($this->buildId, $archive);

    expect($result->fileCount)->toBe(3)
        ->and($result->manifest->paths())->toBe([
            'html/assets/site.css',
            'html/guide.html',
            'html/index.html',
        ]);

    // The exit criterion: a per-file sha256, and one that is the digest of the
    // bytes actually stored rather than of what the archive claimed.
    foreach ($result->manifest->paths() as $path) {
        $entry = $result->manifest->get($path);
        $stored = Storage::disk('artifacts')->get('builds/'.Uuid::toText($this->buildId).'/'.$path);

        expect($entry)->not->toBeNull()
            ->and($entry['sha256'])->toMatch('/^[0-9a-f]{64}$/')
            ->and($entry['sha256'])->toBe(hash('sha256', (string) $stored))
            ->and($entry['bytes'])->toBe(strlen((string) $stored));
    }

    expect($result->manifest->get('html/index.html')['content_type'])->toBe('text/html; charset=utf-8')
        ->and($result->manifest->get('html/assets/site.css')['content_type'])->toBe('text/css; charset=utf-8');
});

it('keys every object by build id alone', function (): void {
    $archive = HostileArchives::build('valid_three_file_tree', $this->fixtures);

    $this->ingestor->ingest($this->buildId, $archive);

    $prefix = 'builds/'.Uuid::toText($this->buildId).'/';

    // 🛑 §8.8.1: "No project slug, version slug, language or user-supplied name
    // MUST appear in any storage key, so renaming can never strand or
    // invalidate stored artifacts."
    foreach (Storage::disk('artifacts')->allFiles() as $key) {
        expect($key)->toStartWith($prefix);
    }
});

it('stores the manifest outside every served tree', function (): void {
    $archive = HostileArchives::build('valid_three_file_tree', $this->fixtures);

    $result = $this->ingestor->ingest($this->buildId, $archive);

    /*
     * 🛑 At builds/{id}/html/manifest.json the manifest would be a public URL
     * on the documentation origin, handing any visitor the sha256 and size of
     * every file in the tree — including files behind §12's access rules.
     */
    expect($result->manifestKey)->toBe('builds/'.Uuid::toText($this->buildId).'/manifest/manifest.json')
        ->and($result->manifest->paths())->each->not->toStartWith('manifest/');

    $stored = (string) Storage::disk('artifacts')->get($result->manifestKey);

    expect(FileManifest::decode($stored)->digest())->toBe($result->contentSha256);
});

it('produces byte-identical manifests from a zip and a tar of one tree', function (): void {
    $tar = HostileArchives::build('valid_three_file_tree', $this->fixtures);
    $zip = HostileArchives::build('valid_zip_tree', $this->fixtures);

    $fromTar = $this->ingestor->ingest(Uuid::v7(), $tar);
    $fromZip = $this->ingestor->ingest(Uuid::v7(), $zip);

    // 🛑 Two readers, one answer. If the formats disagreed about what a tree
    // contains, the content key of §8.7.9 would depend on how a runner chose to
    // pack its output, and two identical builds would look different.
    expect($fromZip->manifest->encode())->toBe($fromTar->manifest->encode())
        ->and($fromZip->contentSha256)->toBe($fromTar->contentSha256)
        ->and($fromTar->archiveFormat)->toBe('tar.gz')
        ->and($fromZip->archiveFormat)->toBe('zip');
});

it('accepts the tree as tar -C dir . emits it', function (): void {
    $archive = HostileArchives::build('dot_prefixed_tree', $this->fixtures);

    $result = $this->ingestor->ingest($this->buildId, $archive);

    // One leading './' is stripped: removing it cannot change which file a path
    // names, and refusing it would fail the most natural packing command.
    expect($result->manifest->paths())->toBe(['html/guide.html', 'html/index.html']);
});

it('refuses a ratio above the cap and accepts one below it', function (): void {
    // 1 MiB of a repeating pattern, which gzip reduces enough that a cap can be
    // aimed either side of the real ratio.
    $payload = str_repeat('docup', 209_716);

    $archive = (new ArchiveWriter)
        ->add('html/index.html', "<!doctype html><p>ok</p>\n")
        ->add('html/big.txt', $payload)
        ->toTarGz($this->fixtures.'/ratio.tar.gz');

    /*
     * Measured against the DECOMPRESSED STREAM, not the sum of the member
     * sizes. The two differ — headers, per-member padding and the terminator
     * are stream bytes that belong to no member — and the stream figure is the
     * binding one, because TarArchiveReader::materialise() stops decompressing
     * at the ceiling and never gets as far as reading a header. An earlier
     * version of this test computed the member total, set a cap just above it,
     * and was still refused: the cap it had chosen was below the real expansion.
     */
    $streamBytes = strlen((string) gzdecode((string) file_get_contents($archive)));
    $ratio = $streamBytes / (int) filesize($archive);

    // Either side of the real ratio. Testing the boundary rather than a 1000:1
    // bomb is what proves the comparison is the right way round — a reversed
    // `>` would still refuse an obvious bomb and look correct.
    $strict = new ArtifactIngestor($this->store, $this->caps->with(compressionRatio: $ratio - 1.0));
    $lenient = new ArtifactIngestor($this->store, $this->caps->with(compressionRatio: $ratio + 1.0));

    expect(fn () => $strict->ingest(Uuid::v7(), $archive))
        ->toThrow(IngestRejected::class, 'contract.compression_ratio_exceeded');

    expect($lenient->ingest(Uuid::v7(), $archive)->fileCount)->toBe(2);
});

it('refuses to overwrite a stored object', function (): void {
    $archive = HostileArchives::build('valid_three_file_tree', $this->fixtures);

    $this->ingestor->ingest($this->buildId, $archive);

    // 🛑 §8.8.5 needs the previous build intact for rollback to mean anything,
    // so a key is written once. Re-ingesting the same build id is the cheapest
    // way to prove the store refuses rather than replaces.
    expect(fn () => $this->ingestor->ingest($this->buildId, $archive))
        ->toThrow(ArtifactWriteRefused::class);
});

it('records a per-format output for each format directory', function (): void {
    $archive = (new ArchiveWriter)
        ->add('html/index.html', "<!doctype html><p>ok</p>\n")
        ->add('html/guide.html', "<p>guide</p>\n")
        ->add('pdf/docs.pdf', "%PDF-1.7\n")
        ->toTarGz($this->fixtures.'/multi.tar.gz');

    $result = $this->ingestor->ingest($this->buildId, $archive);

    expect($result->formats())->toBe(['html', 'pdf'])
        ->and($result->output('html')->fileCount)->toBe(2)
        ->and($result->output('pdf')->fileCount)->toBe(1)
        ->and($result->output('pdf')->storageKey)->toBe('builds/'.Uuid::toText($this->buildId).'/pdf')
        ->and($result->output('html')->contentSha256)->toMatch('/^[0-9a-f]{64}$/')
        ->and($result->totalBytes)->toBe($result->manifest->totalBytes());
});

it('refuses a file over the per-file cap', function (): void {
    $archive = (new ArchiveWriter)
        ->add('html/index.html', "<!doctype html><p>ok</p>\n")
        ->add('html/big.bin', str_repeat('x', 4096))
        ->toTar($this->fixtures.'/perfile.tar');

    $ingestor = new ArtifactIngestor($this->store, $this->caps->with(fileBytes: 1024));

    expect(fn () => $ingestor->ingest($this->buildId, $archive))
        ->toThrow(IngestRejected::class, 'contract.file_size_exceeded');
});

it('refuses a tree over the total-size cap', function (): void {
    $archive = (new ArchiveWriter)
        ->add('html/index.html', str_repeat('x', 1024))
        ->add('html/a.txt', str_repeat('x', 1024))
        ->add('html/b.txt', str_repeat('x', 1024))
        ->toTar($this->fixtures.'/total.tar');

    $ingestor = new ArtifactIngestor($this->store, $this->caps->with(totalBytes: 2048));

    expect(fn () => $ingestor->ingest($this->buildId, $archive))
        ->toThrow(IngestRejected::class, 'contract.total_size_exceeded');
});

it('escapes an attacker-supplied entry name in the rejection message', function (): void {
    $archive = (new ArchiveWriter)
        ->add('html/index.html', "<!doctype html><p>ok</p>\n")
        ->add("html/x\n2026-01-01 INFO nothing to see.php", 'x')
        ->toTar($this->fixtures.'/forged.tar');

    try {
        $this->ingestor->ingest($this->buildId, $archive);
        $this->fail('The forged entry name was accepted.');
    } catch (IngestRejected $rejection) {
        // 🛑 An entry name reaches the build log and the API response. One
        // carrying a newline must not be able to forge a log record, so the
        // message may contain an escape sequence but never the raw control
        // character.
        expect($rejection->getMessage())->not->toContain("\n")
            ->and($rejection->getMessage())->toContain('\\n');
    }
});
