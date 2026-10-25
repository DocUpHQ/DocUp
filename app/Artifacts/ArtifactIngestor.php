<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

use App\Artifacts\Exceptions\IngestRejected;
use App\Support\Uuid;

/**
 * 🛑 The one and only gate between an uploaded tree and the artifact store
 * (§8.8.2).
 *
 * §8.8.2: "Exactly **one** `ArtifactIngestor` MUST validate every incoming
 * tree, and an architecture test MUST prove no caller bypasses it." That test
 * exists and asserts that nothing outside this namespace calls
 * {@see ArtifactStore::put()}. The reason the specification bothers to say
 * "exactly one" is that a second ingest path is not a duplication bug, it is an
 * unvalidated one: the second path gets written in a hurry, for a migration or
 * an import, by somebody who did not know this file existed — and it is the one
 * the attacker uses.
 *
 * **The order of operations is the defence.** Enumerate the whole archive,
 * validate every entry, and only then write a single byte. Both boundaries are
 * load-bearing:
 *
 * - Validating during extraction means the file that fails validation has
 *   already been written. For `.user.ini` — §8.8.2's named example, "code
 *   execution if the storage root is ever a PHP document root" — the window
 *   between writing it and deleting it again is the whole attack. So the tree
 *   is read **twice** — once for its headers, once for its real bytes — and
 *   only then written.
 * - Caps are checked against the archive's **declared** sizes first, because
 *   discovering a 5 GB expansion by performing it is not a defence, and then
 *   against the **actual** bytes while streaming, because a header is
 *   attacker-supplied and can lie.
 *
 * **One upload is one build's whole output.** §8.4.5: "The output contract MUST
 * be a single directory: anything written to
 * `$DOCUP_OUTPUT/{html,pdf,epub,htmlzip}/` is published". So the archive root
 * holds format directories, the first path segment names the format, and the
 * manifest path is the storage key relative to `builds/{build_id}/` — one
 * mapping, used by the ingestor to write and by the serving edge to read.
 *
 * What this class never does is extract to a path. It asks the store for a key
 * built from a build id (§8.8.1) and appends the validated relative path, so an
 * entry name never reaches a filesystem call as a component the operating
 * system will interpret.
 *
 * 🛑 **It is also the only place a documentation byte is ever changed.** §8.15.1
 * injects chrome here, at ingest, because §4.3/2, §4.3/6, §8.9.8 and §19/6 all
 * forbid serve-time rewriting — and the §8.9.8 handoff makes it impossible
 * anyway, since the edge moves bytes the application never reads. Injection is
 * project- and version-agnostic (§8.15.1), so one build still serves every
 * project that mounts it: the project's own `chrome_mode` is applied by the
 * loader at read time, not by changing the artifact.
 */
final class ArtifactIngestor
{
    /**
     * §8.4.5's output directories, and nothing else.
     *
     * `manifest`, `nav` and `provenance` are §10.3 formats but not output
     * directories: DocUp emits those itself, so accepting them from an upload
     * would let a build supply its own manifest — and the manifest is what the
     * serving path trusts instead of probing storage.
     */
    private const OUTPUT_FORMATS = ['html', 'pdf', 'epub', 'htmlzip'];

    /** The formats §8.4.5 restricts to exactly one file. */
    private const SINGLE_FILE_FORMATS = ['pdf', 'epub', 'htmlzip'];

    /**
     * Filenames refused outright, wherever they appear.
     *
     * 🛑 §8.8.2 names these three for the reason it states: "`.user.ini`
     * planted in a build output is code execution if the storage root is ever a
     * PHP document root." DocUp's artifact root is not a document root, and
     * DocUp cannot promise it never will be on an installation it does not
     * control — one misconfigured reverse proxy, or one operator serving the
     * directory directly to debug something at 2am.
     */
    private const RESERVED_NAMES = ['.htaccess', '.user.ini', 'web.config'];

    /**
     * Extensions some PHP handler will execute.
     *
     * §8.8.2's list is `*.php*`, which is `/\.php/i` and catches `x.php`,
     * `x.php.txt`, `x.php5` and `x.phps`. The rest here are **additions**:
     * `.phtml`, `.phar` and `.pht` are mapped to the PHP handler by default or
     * near-default configurations and `*.php*` misses all three. Recorded as a
     * proposed amendment to §8.8.2 in the Phase 03 build-log entry rather than
     * taken silently — §8.8.2's list is a floor, but widening it changes what
     * authors see, and a widening nobody wrote down is one nobody can audit.
     */
    private const RESERVED_EXTENSION_PATTERN = '/\.(php|phtml|phar|pht)/i';

    /**
     * Ceiling on the whole relative path, in bytes.
     *
     * 🛑 Not a §8.8.2 cap — it is S3's. An object key may be 1,024 bytes and
     * `builds/{uuid}/` already spends 43 of them. Enforced here rather than
     * left to the store so the local driver and the S3 driver accept exactly
     * the same trees: a tree that published on a single-node installation and
     * failed on a clustered one would be the worst kind of portability bug,
     * discovered during a migration.
     */
    private const MAX_PATH_BYTES = 900;

    /** §8.8.2's limit on one path component. */
    private const MAX_SEGMENT_BYTES = 255;

    public function __construct(
        private readonly ArtifactStore $store,
        private readonly IngestCaps $caps,
        private readonly ChromeInjector $chrome,
    ) {}

    /**
     * Validate an uploaded build output and write it to the store.
     *
     * @param  string  $buildId  raw 16 bytes, per ADR 0006
     * @param  string  $archivePath  a local file: a zip, tar or gzipped tar
     *
     * @throws IngestRejected on any §8.8.2 or §8.4.5 violation, before anything
     *                        is written
     */
    public function ingest(string $buildId, string $archivePath): IngestResult
    {
        $reader = ArchiveReaderFactory::open($archivePath, $this->caps);

        try {
            $paths = $this->validate($reader->entries(), $reader);
            $this->assertOutputContract($paths);

            return $this->extract($reader, $this->canonicaliseOfflineLeaves($paths), $buildId);
        } finally {
            /*
             * Always. A rejected ingest otherwise leaves its decompressed
             * temporary file behind, and a worker refusing a hundred malicious
             * uploads would fill its own disk doing so — turning a successful
             * defence into an outage.
             */
            $reader->close();
        }
    }

    /**
     * Pass one: refuse the whole tree, or return the file entries to write.
     *
     * Returns validated relative path => entry, so pass two never touches a raw
     * entry name again. Directories are dropped: an object store has none, and
     * the local driver creates intermediate ones on write.
     *
     * @param  list<ArchiveEntry>  $entries
     * @return array<string, ArchiveEntry>
     *
     * @throws IngestRejected
     */
    private function validate(array $entries, ArchiveReader $reader): array
    {
        $paths = [];
        $declaredTotal = 0;

        foreach ($entries as $entry) {
            /*
             * Entry kind first. A link, device or FIFO is refused whatever it is
             * called, so there is no point validating its name — and checking
             * the kind first is what makes "an absolute symlink" report
             * `contract.symlink_rejected` rather than `contract.absolute_path`,
             * which is the distinction Phase 03's exit criteria ask for.
             */
            $rejection = $entry->type->rejection();

            if ($rejection !== null) {
                throw IngestRejected::because($rejection, $entry->name);
            }

            $path = $this->validateName($entry->name);

            // The archive root itself, as `tar -C dir -czf out.tar.gz .` emits
            // it. Nothing to store and nothing to check.
            if ($path === null) {
                continue;
            }

            // Directories are name-checked, because `../..` is a traversal
            // attempt whether or not anything is stored at it, but not stored.
            if ($entry->type === EntryType::Directory) {
                continue;
            }

            if (isset($paths[$path])) {
                throw IngestRejected::because(RejectionCode::DuplicateEntry, $entry->name);
            }

            if ($entry->declaredSize > $this->caps->fileBytes) {
                throw IngestRejected::because(
                    RejectionCode::FileSizeExceeded,
                    $entry->name,
                    $entry->declaredSize.' declared bytes, cap is '.$this->caps->fileBytes,
                );
            }

            if ($entry->compressionRatio() > $this->caps->compressionRatio) {
                throw IngestRejected::because(
                    RejectionCode::CompressionRatioExceeded,
                    $entry->name,
                    sprintf('%.1f:1, cap is %.1f:1', $entry->compressionRatio(), $this->caps->compressionRatio),
                );
            }

            $declaredTotal += $entry->declaredSize;

            if ($declaredTotal > $this->caps->totalBytes) {
                throw IngestRejected::because(
                    RejectionCode::TotalSizeExceeded,
                    detail: 'declared total exceeds '.$this->caps->totalBytes.' bytes',
                );
            }

            $paths[$path] = $entry;

            if (count($paths) > $this->caps->files) {
                throw IngestRejected::because(
                    RejectionCode::FileCountExceeded,
                    detail: 'more than '.$this->caps->files.' files',
                );
            }
        }

        $this->assertArchiveRatio($declaredTotal, $reader);

        return $paths;
    }

    /**
     * The whole-archive compression ratio.
     *
     * 🛑 Needed in addition to the per-entry check because a tar member carries
     * no compressed size of its own: every entry in a `.tar.gz` reports 1:1, so
     * a 40 KB upload expanding to 4 GB passes the per-entry check forty
     * thousand times. {@see TarArchiveReader::materialise()} bounds the
     * decompression itself; this applies the same cap to what the headers
     * declare, which is what catches an archive whose members are sparse rather
     * than compressed.
     */
    private function assertArchiveRatio(int $declaredTotal, ArchiveReader $reader): void
    {
        $archiveBytes = $reader->archiveBytes();

        if ($archiveBytes <= 0 || $declaredTotal === 0) {
            return;
        }

        $ratio = $declaredTotal / $archiveBytes;

        if ($ratio > $this->caps->compressionRatio) {
            throw IngestRejected::because(
                RejectionCode::CompressionRatioExceeded,
                detail: sprintf('archive expands %.1f:1, cap is %.1f:1', $ratio, $this->caps->compressionRatio),
            );
        }
    }

    /**
     * Every §8.8.2 name rule, in one place.
     *
     * Returns the path to store at, or null for the archive root entry. The
     * return value is the *same string* the archive declared, minus a trailing
     * slash and an optional leading `./` — deliberately not a normalised form,
     * because every construct normalisation would collapse (`..`, a `.` in the
     * middle, `//`, a backslash) is refused outright instead. A validator that
     * normalises has to be correct about what the filesystem would have done;
     * one that refuses only has to be correct about what it refuses.
     *
     * @throws IngestRejected
     */
    private function validateName(string $name): ?string
    {
        if ($name === '') {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, detail: 'entry with an empty name');
        }

        /*
         * 🛑 Backslashes and control characters are checked on the raw string,
         * before anything splits it. NUL truncates a name in any C library that
         * sees it, so `safe.html\0.php` would be validated as one name and
         * written as another; and `a\..\..\b` means different things to
         * different extractors, which makes it a name that cannot be validated
         * once and is therefore refused rather than interpreted.
         */
        if (str_contains($name, '\\')) {
            throw IngestRejected::because(RejectionCode::BackslashInName, $name);
        }

        if (preg_match('/[\x00-\x1F\x7F]/', $name) === 1) {
            throw IngestRejected::because(RejectionCode::ControlCharacterInName, $name);
        }

        // A leading slash, or a Windows drive letter. A UNC path (`\\host\…`)
        // is already refused by the backslash rule above.
        if (str_starts_with($name, '/') || preg_match('#^[A-Za-z]:#', $name) === 1) {
            throw IngestRejected::because(RejectionCode::AbsolutePath, $name);
        }

        $path = rtrim($name, '/');

        /*
         * Exactly one leading `./` is stripped, and a bare `.` is the archive
         * root. `tar -C "$DOCUP_OUTPUT" -czf out.tar.gz .` is the most natural
         * way to produce an upload and it prefixes every member this way, so
         * refusing it would fail the common case to defend against nothing:
         * removing a leading `./` cannot change which file a path names. Every
         * other `.` segment is still refused below, because `a/./b` would make
         * the manifest disagree with the served path.
         */
        if ($path === '.') {
            return null;
        }

        if (str_starts_with($path, './')) {
            $path = substr($path, 2);
        }

        if ($path === '') {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, $name, 'entry names only slashes');
        }

        if (strlen($path) > self::MAX_PATH_BYTES) {
            throw IngestRejected::because(
                RejectionCode::FilenameTooLong,
                $name,
                strlen($path).' bytes, cap is '.self::MAX_PATH_BYTES,
            );
        }

        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.' || $segment === '..') {
                throw IngestRejected::because(RejectionCode::PathEscapesRoot, $name);
            }

            if (strlen($segment) > self::MAX_SEGMENT_BYTES) {
                throw IngestRejected::because(
                    RejectionCode::FilenameTooLong,
                    $name,
                    'segment of '.strlen($segment).' bytes',
                );
            }

            /*
             * Case-insensitive on purpose. The artifact root may sit on a
             * case-insensitive filesystem — macOS and Windows both — where
             * `.USER.INI` is the same file as `.user.ini`. A case-sensitive
             * check would be right on the CI runner and wrong on a developer's
             * laptop, which is the worst of the available arrangements.
             */
            if (in_array(strtolower($segment), self::RESERVED_NAMES, true)) {
                throw IngestRejected::because(RejectionCode::ReservedFilename, $name);
            }

            if (preg_match(self::RESERVED_EXTENSION_PATTERN, $segment) === 1) {
                throw IngestRejected::because(RejectionCode::ReservedFilename, $name);
            }
        }

        return $path;
    }

    /**
     * §8.4.5's output contract, checked before any byte is written.
     *
     * "anything written to `$DOCUP_OUTPUT/{html,pdf,epub,htmlzip}/` is
     * published; `html/index.html` is mandatory; each offline format directory
     * MUST contain exactly one file."
     *
     * An html tree with no index would publish a version whose own URL is a
     * 404 — worse than a failed build, because it looks like a success.
     *
     * @param  array<string, ArchiveEntry>  $paths
     *
     * @throws IngestRejected
     */
    private function assertOutputContract(array $paths): void
    {
        $counts = [];

        foreach (array_keys($paths) as $path) {
            $format = $this->formatOf($path);

            if ($format === null) {
                throw IngestRejected::because(RejectionCode::UnknownOutputDirectory, $path);
            }

            $counts[$format] = ($counts[$format] ?? 0) + 1;
        }

        if (! isset($paths['html/index.html'])) {
            throw IngestRejected::because(RejectionCode::MissingHtmlIndex, detail: 'no html/index.html');
        }

        foreach (self::SINGLE_FILE_FORMATS as $format) {
            $count = $counts[$format] ?? 0;

            if ($count > 1) {
                throw IngestRejected::because(
                    RejectionCode::multipleFilesFor($format),
                    detail: "found {$count} files",
                );
            }
        }
    }

    /**
     * 🛑 §8.4.5's identifier-free leaf, applied to the three offline formats.
     *
     * > "It MUST be stored under an identifier-free leaf name, with the
     * > `<project>-<version>.<ext>` download filename applied at serve time by
     * > `Content-Disposition` and **never** written into the storage key —
     * > §8.8.1 forbids any slug in a storage path, and a renamed project must
     * > not strand its own downloads."
     *
     * Sphinx names its PDF after `project` in `conf.py`; mdBook, VitePress and
     * a hand-written `build.commands` name theirs after whatever the author
     * chose. Each of those is a user-supplied string, and §8.8.1 is categorical
     * that none may appear in a storage key.
     *
     * 🛑 **Here, not in the preset.** `resources/toolchains/sphinx.yaml` also
     * writes `document.pdf`, which makes the contract visible in a build log —
     * but a preset cannot be the guarantee, because §8.4.4's `build.commands`
     * discards the preset entirely and §8.4.3's `build.jobs` can replace the
     * step. The contract applies to *anything* written to those directories, so
     * it is enforced where everything written to them passes.
     *
     * 🛑 **The extension comes from the FORMAT, never from the uploaded name.**
     * `pdf/payload.html` would otherwise become `pdf/document.html`, served
     * with a content type taken from its own extension — which is the
     * "HTML file renamed `.pdf`" case arriving from the other direction. With
     * the extension fixed per format, the stored object's type is decided by
     * the directory the build chose, and the serving path refuses to render it
     * whatever its bytes say (see `DownloadController`).
     *
     * @param  array<string, ArchiveEntry>  $paths
     * @return array<string, ArchiveEntry>
     */
    private function canonicaliseOfflineLeaves(array $paths): array
    {
        $canonical = [];

        foreach ($paths as $path => $entry) {
            $format = $this->formatOf($path);

            $canonical[
                $format !== null && in_array($format, self::SINGLE_FILE_FORMATS, true)
                    ? self::offlineLeafFor($format)
                    : $path
            ] = $entry;
        }

        return $canonical;
    }

    /**
     * The one stored path an offline format may occupy.
     *
     * §10.3's storage layout writes it out:
     * `builds/<build_uuid>/{pdf,epub,htmlzip}/document.<ext>`.
     *
     * 🛑 `htmlzip` stores `.zip`, not `.htmlzip`. The directory names the
     * format and the leaf names the media type, and they are different things:
     * `application/zip` is what the extension allowlist knows and what a
     * reader's operating system will open.
     */
    public static function offlineLeafFor(string $format): string
    {
        return $format.'/document.'.match ($format) {
            'htmlzip' => 'zip',
            default => $format,
        };
    }

    /**
     * Pass two: stream each validated entry into the store, hashing as it goes.
     *
     * @param  array<string, ArchiveEntry>  $paths
     *
     * @throws IngestRejected
     */
    private function extract(ArchiveReader $reader, array $paths, string $buildId): IngestResult
    {
        /*
         * Sorted, so two ingests of one tree hash and write in the same order
         * and produce the same per-format digest. It costs nothing, and it
         * makes a partially-failed ingest reproducible — the difference between
         * debugging one and guessing at it.
         */
        ksort($paths, SORT_STRING);

        /*
         * 🛑 Validation first, and nothing written until it passes. A header
         * that lied about its size is caught here, with nothing yet stored. An
         * earlier version of this method wrote each file as it hashed it, which
         * meant a tree refused on its last entry had already published every
         * entry before it — the abuse corpus's `lying_size_header` case found
         * that.
         */
        $this->measure($reader, $paths);

        $manifest = new FileManifest;
        $coverage = new InjectionCoverage;
        $buildIdText = Uuid::toText($buildId);
        $actualTotal = 0;

        /** @var array<string, array{files: int, bytes: int, digests: list<string>}> $perFormat */
        $perFormat = [];

        /*
         * A storage failure part-way through this loop still leaves orphaned
         * objects. That is unavoidable, and it is safe: the build never
         * publishes, so no pointer references them, and §8.8.9's mark-and-sweep
         * collects objects no live pointer or pin reaches.
         */
        foreach ($paths as $path => $entry) {
            $format = $this->formatOf($path);

            // assertOutputContract() already refused an unknown directory. This
            // is the narrowing that proves it to the analyser rather than
            // asserting it in a comment.
            if ($format === null) {
                throw IngestRejected::because(RejectionCode::UnknownOutputDirectory, $path);
            }

            [$digest, $bytes, $buffered] = $this->prepare($reader, $entry, $path, $buildIdText, $coverage);

            $actualTotal += $bytes;

            /*
             * Re-checked against what will actually be stored. Injection adds
             * about 120 bytes per document — DocUp's own change, not
             * attacker-supplied — and the cap is a cap on what lands on the
             * disk, so the injected size is the one that counts.
             */
            if ($actualTotal > $this->caps->totalBytes) {
                throw IngestRejected::because(
                    RejectionCode::TotalSizeExceeded,
                    detail: $actualTotal.' stored bytes exceeds '.$this->caps->totalBytes,
                );
            }

            $manifest->add($path, $digest, $bytes);

            $perFormat[$format] ??= ['files' => 0, 'bytes' => 0, 'digests' => []];
            $perFormat[$format]['files']++;
            $perFormat[$format]['bytes'] += $bytes;
            $perFormat[$format]['digests'][] = $path.':'.$digest;

            /*
             * A buffered document is written from the buffer, because its bytes
             * are no longer the archive's. Everything else is streamed again,
             * so a 1 GB asset never becomes a 1 GB allocation.
             */
            $this->store->put(
                $this->keyFor($buildId, $path),
                $buffered ?? $reader->stream($entry),
            );
        }

        $outputs = [];

        foreach ($perFormat as $format => $totals) {
            $outputs[] = new ArtifactOutput(
                format: $format,
                storageKey: $this->store->keyFor($buildId, $format),
                fileCount: $totals['files'],
                totalBytes: $totals['bytes'],
                // Over the path:digest pairs rather than over concatenated
                // content: it needs no second pass over the bytes, it is stable
                // given the ksort above, and it changes when a file is renamed
                // as well as when one is edited.
                contentSha256: hash('sha256', implode("\n", $totals['digests'])),
            );
        }

        return new IngestResult(
            buildId: $buildId,
            archiveFormat: $reader->format(),
            manifestKey: $this->writeManifest($buildId, $manifest),
            manifest: $manifest,
            outputs: $outputs,
            fileCount: $manifest->count(),
            totalBytes: $actualTotal,
            contentSha256: $manifest->digest(),
            coverage: $coverage,
        );
    }

    /**
     * One entry's stored bytes: injected where §8.15.1 applies, hashed either
     * way.
     *
     * 🛑 The digest is of the bytes that get **stored**, never of the bytes the
     * archive supplied. §8.9.12 derives the strong ETag from this digest, and
     * §8.4.18's manifest is what the serving path trusts — so a digest of the
     * pre-injection bytes would make every injected document's ETag wrong, and
     * wrong in the direction that serves stale content from a shared cache.
     *
     * Non-HTML and oversized HTML stream, so memory stays flat. Only a document
     * small enough to inject is buffered, and only one at a time.
     *
     * @return array{0: string, 1: int, 2: string|null} digest, byte count, and
     *                                                  the buffer to store, or
     *                                                  null to stream
     *
     * @throws IngestRejected
     */
    private function prepare(
        ArchiveReader $reader,
        ArchiveEntry $entry,
        string $path,
        string $buildIdText,
        InjectionCoverage $coverage,
    ): array {
        $compressed = self::isCompressedHtml($path);

        if (! $compressed && ! ChromeInjector::handles($path)) {
            // Not a document. Stream, hash, store the stream.
            $stream = $reader->stream($entry);

            try {
                [$digest, $bytes] = $this->drain($stream, $entry);
            } finally {
                if (is_resource($stream)) {
                    fclose($stream);
                }
            }

            return [$digest, $bytes, null];
        }

        /*
         * §8.15.4's third non-injectable class, checked from the declared size
         * so an oversized document is never buffered at all. It is still
         * published — §8.15.4 wants `api_only`, not a missing page — and it
         * still raises the warning.
         */
        if ($entry->declaredSize > $this->maxInjectableBytes()) {
            $stream = $reader->stream($entry);

            try {
                [$digest, $bytes] = $this->drain($stream, $entry);
            } finally {
                if (is_resource($stream)) {
                    fclose($stream);
                }
            }

            $coverage->record($path, InjectionOutcome::RefusedTooLarge);

            return [$digest, $bytes, null];
        }

        $stream = $reader->stream($entry);

        try {
            $raw = (string) stream_get_contents($stream);
        } finally {
            if (is_resource($stream)) {
                fclose($stream);
            }
        }

        if (strlen($raw) !== $entry->declaredSize) {
            // The same lying-header check drain() performs. Repeated here
            // because this branch does not go through drain(), and pass one's
            // cap checks mean nothing if the real sizes may differ.
            throw IngestRejected::because(
                RejectionCode::UnreadableArchive,
                $entry->name,
                "header declares {$entry->declaredSize} bytes, stream yielded ".strlen($raw),
            );
        }

        $stored = $compressed
            ? $this->injectCompressed($raw, $path, $buildIdText, $coverage)
            : $this->injectPlain($raw, $path, $buildIdText, $coverage);

        return [hash('sha256', $stored), strlen($stored), $stored];
    }

    /** §8.15.1 on an uncompressed document. */
    private function injectPlain(
        string $raw,
        string $path,
        string $buildIdText,
        InjectionCoverage $coverage,
    ): string {
        /*
         * 🛑 An `.html` file whose bytes are gzip is a mis-named compressed
         * document. §8.15.10 permits exactly two dispositions and "stored as
         * though it were HTML" is neither — the serving path would hand a
         * reader gzip bytes under `text/html`, which renders as nothing.
         */
        if (self::looksGzipped($raw)) {
            throw IngestRejected::because(
                RejectionCode::CompressedHtmlRefused,
                $path,
                'an .html file whose bytes are gzip',
            );
        }

        $injection = $this->chrome->inject($raw, $buildIdText);
        $coverage->record($path, $injection->outcome);

        return $injection->bytes;
    }

    /**
     * 🛑 §8.15.10: "A pre-compressed HTML artifact MUST be decompressed,
     * injected and recompressed at ingest, or refused with a stable error
     * identifier."
     *
     * Both halves are here and there is no third option. The reason the
     * requirement is so emphatic — "This is the **single** normative disposition
     * for compressed HTML; no other requirement may state another, and nothing
     * is rewritten on the serving path to compensate" — is that the tempting
     * alternative is to decompress at serve time, and that would put
     * documentation bytes back through PHP in exactly the place §8.9.8 spent its
     * design keeping them out of.
     */
    private function injectCompressed(
        string $raw,
        string $path,
        string $buildIdText,
        InjectionCoverage $coverage,
    ): string {
        $plain = @gzdecode($raw);

        if ($plain === false) {
            throw IngestRejected::because(
                RejectionCode::CompressedHtmlRefused,
                $path,
                'could not be decompressed',
            );
        }

        $injection = $this->chrome->inject($plain, $buildIdText);
        $coverage->record($path, $injection->outcome);

        // Recompressed at the same level the sidecar convention assumes. A
        // sidecar that came back larger than its source would be a sidecar the
        // edge should not serve, and level 9 keeps that from happening for any
        // document injection has merely grown by ~120 bytes.
        $recompressed = gzencode($injection->bytes, 9);

        if ($recompressed === false) {
            throw IngestRejected::because(
                RejectionCode::CompressedHtmlRefused,
                $path,
                'could not be recompressed',
            );
        }

        return $recompressed;
    }

    /** The ceiling §8.15.4 measures against, read once per ingest. */
    private function maxInjectableBytes(): int
    {
        $max = config('artifacts.chrome.max_html_bytes');

        return is_numeric($max) ? (int) $max : 4 * 1024 * 1024;
    }

    /** A pre-compressed HTML sidecar, by extension (§8.15.10). */
    private static function isCompressedHtml(string $path): bool
    {
        if (! str_ends_with(strtolower($path), '.gz')) {
            return false;
        }

        return ChromeInjector::handles(substr($path, 0, -3));
    }

    /** The gzip magic number. Two bytes, and they are not valid UTF-8 HTML. */
    private static function looksGzipped(string $bytes): bool
    {
        return str_starts_with($bytes, "\x1f\x8b");
    }

    /**
     * Validate every entry's real bytes against the caps, writing nothing.
     *
     * 🛑 This is the pass that makes pass one mean something. Pass one checked
     * the caps against the archive's **declared** sizes, which are
     * attacker-supplied; if the real sizes were free to differ, pass one checked
     * nothing at all. Here the bytes are counted as they stream, so a lying
     * header is caught — and caught before {@see self::extract()} has stored a
     * single object.
     *
     * It builds no manifest and keeps no digests. The manifest is built during
     * the storing pass, from the bytes that actually land, because injection
     * changes them and §8.4.18's manifest must describe what is stored.
     *
     * @param  array<string, ArchiveEntry>  $paths  sorted
     *
     * @throws IngestRejected
     */
    private function measure(ArchiveReader $reader, array $paths): void
    {
        $actualTotal = 0;

        foreach ($paths as $entry) {
            $stream = $reader->stream($entry);

            try {
                [, $bytes] = $this->drain($stream, $entry);
            } finally {
                if (is_resource($stream)) {
                    fclose($stream);
                }
            }

            $actualTotal += $bytes;

            if ($actualTotal > $this->caps->totalBytes) {
                throw IngestRejected::because(
                    RejectionCode::TotalSizeExceeded,
                    detail: $actualTotal.' actual bytes exceeds '.$this->caps->totalBytes,
                );
            }
        }
    }

    /**
     * Hash an entry's bytes and confirm they are the bytes the header promised.
     *
     * 🛑 The size comparison is not pedantry. Pass one refused a tree whose
     * declared sizes breach the caps; if the real sizes may differ from the
     * declared ones, pass one checked nothing at all. A mismatch means the
     * archive is lying about its own contents, so the tree is refused rather
     * than stored with a corrected size — there is no reason to trust the rest
     * of an archive that lied about this.
     *
     * @param  resource  $stream
     * @return array{0: string, 1: int} lowercase hex digest, byte count
     *
     * @throws IngestRejected
     */
    private function drain($stream, ArchiveEntry $entry): array
    {
        $context = hash_init('sha256');
        $bytes = 0;

        while (! feof($stream)) {
            $chunk = fread($stream, 262_144);

            if ($chunk === false || $chunk === '') {
                break;
            }

            $bytes += strlen($chunk);

            if ($bytes > $this->caps->fileBytes) {
                throw IngestRejected::because(
                    RejectionCode::FileSizeExceeded,
                    $entry->name,
                    'actual bytes exceed '.$this->caps->fileBytes,
                );
            }

            hash_update($context, $chunk);
        }

        if ($bytes !== $entry->declaredSize) {
            throw IngestRejected::because(
                RejectionCode::UnreadableArchive,
                $entry->name,
                "header declares {$entry->declaredSize} bytes, stream yielded {$bytes}",
            );
        }

        return [hash_final($context), $bytes];
    }

    /**
     * The §10.3 format a validated manifest path belongs to, or null.
     *
     * Null rather than a default, so a path outside the four output directories
     * has to be handled explicitly at both call sites. A default of `html`
     * would silently publish a stray top-level file as documentation.
     */
    private function formatOf(string $path): ?string
    {
        $slash = strpos($path, '/');

        if ($slash === false) {
            return null;
        }

        $format = substr($path, 0, $slash);

        return in_array($format, self::OUTPUT_FORMATS, true) ? $format : null;
    }

    /**
     * The storage key for a validated manifest path.
     *
     * 🛑 Built through {@see ArtifactStore::keyFor()} rather than by string
     * concatenation here, so §8.8.1's grammar has exactly one implementation.
     * The manifest path already begins with the format, which is why the key is
     * the build prefix plus the path with that segment consumed — making the
     * manifest path and the key relative to `builds/{build_id}/` the same
     * string, which is what lets the serving edge answer from the manifest
     * alone.
     */
    private function keyFor(string $buildId, string $path): string
    {
        $format = $this->formatOf($path);

        // formatOf() returned non-null for every path that reaches here; both
        // callers refuse the alternative. Repeated rather than asserted because
        // a null here would build the key `builds/{id}//…`, which stores the
        // file at a path nothing would ever read.
        if ($format === null) {
            throw IngestRejected::because(RejectionCode::UnknownOutputDirectory, $path);
        }

        return $this->store->keyFor($buildId, $format).substr($path, strlen($format));
    }

    /**
     * Store the canonical manifest bytes under the build's `manifest` format.
     *
     * 🛑 `builds/{id}/manifest/manifest.json`, not inside a served tree. At
     * `builds/{id}/html/manifest.json` it would be a public URL on the
     * documentation origin, handing any visitor the sha256 and size of every
     * file in the tree, including ones behind §12's access rules. `manifest` is
     * one of §10.3's formats, so this is §8.8.1's key grammar unchanged.
     */
    private function writeManifest(string $buildId, FileManifest $manifest): string
    {
        $key = $this->store->keyFor($buildId, 'manifest').'/manifest.json';

        $this->store->put($key, $manifest->encode());

        return $key;
    }
}
