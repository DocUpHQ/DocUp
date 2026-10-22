<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

use App\Artifacts\Exceptions\IngestRejected;

/**
 * Reads a tar by parsing its 512-byte headers directly.
 *
 * 🛑 **Why not `PharData`.** §8.8.2 requires refusing hardlinks, device nodes
 * and FIFOs, and tar is the only format in use here that can express them. It
 * says which with a single byte — the typeflag at offset 156 — and the
 * convenience wrappers normalise that byte away: `PharData` reports a hard link
 * as a file. A reader that cannot see the difference cannot refuse one, so the
 * header parsing below is not reinvention for its own sake; it is the only way
 * to get at the evidence the specification requires acting on.
 *
 * 🛑 **Long names are parsed, not ignored.** GNU `L` records and pax `x`
 * records carry a name longer than the 100-byte header field, and they carry it
 * in the *preceding* entry's data. An implementation that reads only the header
 * field sees a truncated name — so `../../../etc/cron.d/x` can be smuggled as a
 * pax record behind a header field reading `payload.html`. The validator must
 * be shown the name an extractor would actually use, which is the long one.
 *
 * Gzip is handled by decompressing to a temporary file under a hard ceiling
 * (see {@see self::materialise()}), because a tar member carries no compressed
 * size of its own and the §8.8.2 ratio cap has to bite somewhere.
 */
final class TarArchiveReader implements ArchiveReader
{
    /** The fixed block size of every tar, header and data alike. */
    private const BLOCK = 512;

    /**
     * Ceiling on one GNU/pax metadata record.
     *
     * Not configurable: no author has a reason to want a longer one, and the
     * records are read into memory, so an unbounded `size` here would be a
     * memory exhaustion from a few hundred bytes of upload.
     */
    private const MAX_METADATA_BYTES = 1_048_576;

    /** @var resource|null */
    private $handle = null;

    /** @var list<ArchiveEntry>|null */
    private ?array $entries = null;

    /** @var array<int, int> entry index => byte offset of its data */
    private array $offsets = [];

    public function __construct(
        private readonly string $path,
        private readonly bool $compressed,
        private readonly IngestCaps $caps,
    ) {}

    public function entries(): array
    {
        if ($this->entries !== null) {
            return $this->entries;
        }

        $handle = $this->open();
        $entries = [];
        $index = 0;

        // Carried forward from a GNU 'L'/'K' record or a pax 'x' record to the
        // entry it describes, then cleared. Global pax ('g') records persist,
        // which is what distinguishes the two in the format.
        $pendingName = null;
        $globalName = null;
        $emptyBlocks = 0;

        while (true) {
            $header = fread($handle, self::BLOCK);

            if ($header === false || $header === '') {
                // A tar that simply stops, with no terminator block. Tolerated
                // rather than rejected: the entries read so far are intact and
                // have been validated, and some writers truncate the padding.
                break;
            }

            if (strlen($header) < self::BLOCK) {
                throw IngestRejected::because(RejectionCode::UnreadableArchive, 'truncated header block');
            }

            if (trim($header, "\0") === '') {
                // Two consecutive zero blocks end the archive. A single one is
                // tolerated by every reader in existence, so it is here too.
                if (++$emptyBlocks >= 2) {
                    break;
                }

                continue;
            }

            $emptyBlocks = 0;
            $fields = $this->parseHeader($header);
            $size = $this->parseSize($fields['size']);
            $dataOffset = ftell($handle);

            if ($dataOffset === false) {
                throw IngestRejected::because(RejectionCode::UnreadableArchive, 'unseekable archive');
            }

            $typeflag = $fields['typeflag'];

            // Metadata records are consumed here and never become entries.
            if (in_array($typeflag, ['L', 'K', 'x', 'g'], true)) {
                if ($size > self::MAX_METADATA_BYTES) {
                    throw IngestRejected::because(RejectionCode::FilenameTooLong, "metadata record of {$size} bytes");
                }

                $payload = $size > 0 ? (string) fread($handle, $size) : '';
                $this->skipPadding($handle, $size);

                if ($typeflag === 'L') {
                    $pendingName = rtrim($payload, "\0");
                } elseif ($typeflag === 'x') {
                    $pendingName = $this->pathFromPax($payload) ?? $pendingName;
                } elseif ($typeflag === 'g') {
                    $globalName = $this->pathFromPax($payload) ?? $globalName;
                }

                // 'K' (long link target) is deliberately dropped: the entry it
                // describes is a link, and §8.8.2 refuses every link whatever
                // it points at, so its target is never consulted.
                continue;
            }

            $name = $pendingName
                ?? $globalName
                ?? $this->joinPrefix($fields['prefix'], $fields['name']);

            $entries[] = new ArchiveEntry(
                index: $index,
                name: $name,
                type: $this->classify($typeflag, $name),
                declaredSize: $size,
                // A tar member is stored verbatim; compression applies to the
                // whole stream, so archiveBytes() carries that measure instead.
                compressedSize: $size,
            );

            $this->offsets[$index] = $dataOffset;
            $index++;
            $pendingName = null;

            /*
             * 🛑 The file-count cap bites during enumeration, not after it. A
             * tar with ten million zero-length members is 5 GB of upload and
             * ten million seeks, and a reader that builds the whole list before
             * anyone checks its length has already spent that. Stopping at the
             * cap means the cost of refusing is bounded by the cap.
             */
            if ($index > $this->caps->files) {
                throw IngestRejected::because(
                    RejectionCode::FileCountExceeded,
                    detail: 'more than '.$this->caps->files.' entries',
                );
            }

            if (fseek($handle, $this->paddedLength($size), SEEK_CUR) !== 0) {
                throw IngestRejected::because(RejectionCode::UnreadableArchive, $name);
            }
        }

        if ($entries === [] && ! $this->endsCleanly()) {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, basename($this->path));
        }

        return $this->entries = $entries;
    }

    public function stream(ArchiveEntry $entry)
    {
        // entries() populates $offsets, and the ingestor always enumerates
        // before extracting. Asserted rather than assumed, because a future
        // caller that skipped enumeration would otherwise read from offset 0 —
        // the first header block — and store it as content.
        if (! isset($this->offsets[$entry->index])) {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, $entry->name);
        }

        $handle = $this->open();

        if (fseek($handle, $this->offsets[$entry->index], SEEK_SET) !== 0) {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, $entry->name);
        }

        /*
         * Copied into a bounded temporary stream rather than handing back the
         * archive handle. Two reasons, both bugs otherwise: the handle is
         * shared, so a caller reading past the member's length would read the
         * NEXT member's header as content; and `php://temp` spills to disk past
         * its memory threshold, so a 1 GB member does not become a 1 GB
         * allocation inside a queue worker.
         */
        $buffer = fopen('php://temp/maxmemory:1048576', 'w+b');

        if ($buffer === false) {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, $entry->name);
        }

        if ($entry->declaredSize > 0) {
            stream_copy_to_stream($handle, $buffer, $entry->declaredSize);
        }

        rewind($buffer);

        return $buffer;
    }

    public function archiveBytes(): int
    {
        $size = @filesize($this->path);

        return $size === false ? 0 : $size;
    }

    public function format(): string
    {
        return $this->compressed ? 'tar.gz' : 'tar';
    }

    public function close(): void
    {
        if (is_resource($this->handle)) {
            fclose($this->handle);
        }

        // tmpfile() handles unlink themselves on close, which is the other
        // reason materialise() uses one: there is no path left behind to forget.
        $this->handle = null;
    }

    /** @return resource */
    private function open()
    {
        if (is_resource($this->handle)) {
            return $this->handle;
        }

        if ($this->compressed) {
            return $this->handle = $this->materialise();
        }

        $handle = fopen($this->path, 'rb');

        if ($handle === false) {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, basename($this->path));
        }

        return $this->handle = $handle;
    }

    /**
     * Decompress a gzipped tar into an anonymous temporary file, under a
     * hard ceiling.
     *
     * @return resource
     *
     * 🛑 The ceiling is the §8.8.2 compression-ratio defence, and it is applied
     * **during** decompression, chunk by chunk. Decompressing first and checking
     * the result afterwards would mean a 40 KB upload had already filled the
     * disk by the time the check ran: the check would be reporting the attack
     * it had just finished carrying out.
     *
     * Two ceilings are computed separately so the rejection names the real
     * reason. A tree that is simply too large gets `total_size_exceeded`; one
     * that is small but explosive gets `compression_ratio_exceeded`. Collapsing
     * them into one number would tell an author with a legitimately big
     * documentation set that they had uploaded a zip bomb.
     */
    private function materialise()
    {
        $ratioCeiling = (int) floor($this->archiveBytes() * $this->caps->compressionRatio);

        // The two-block floor keeps a tiny-but-valid archive (an empty tar is
        // 1,024 bytes of zeros, which gzips to about 45) from tripping its own
        // ratio ceiling before a single header has been read.
        $ceiling = min($this->caps->totalBytes, max($ratioCeiling, self::BLOCK * 2));

        $source = fopen('compress.zlib://'.$this->path, 'rb');

        if ($source === false) {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, basename($this->path));
        }

        /*
         * 🛑 `tmpfile()`, not `tempnam()`. `tempnam()` returns a NAME, and
         * between that return and the `fopen` of it another process with write
         * access to the temporary directory can replace the file with a symlink
         * — so the decompressed tar lands wherever that link points, written
         * with this process's privileges. `tmpfile()` hands back an open handle
         * to a file with no usable name, which closes the race by removing the
         * window rather than by narrowing it, and unlinks itself on close.
         *
         * Pest's `security` preset flagged the earlier `tempnam()` here. It was
         * right to.
         */
        $sink = tmpfile();

        if ($sink === false) {
            fclose($source);

            throw IngestRejected::because(RejectionCode::UnreadableArchive, 'no temporary file available');
        }

        $written = 0;

        try {
            while (! feof($source)) {
                $chunk = fread($source, 262_144);

                if ($chunk === false || $chunk === '') {
                    break;
                }

                $written += strlen($chunk);

                if ($written > $ceiling) {
                    throw IngestRejected::because(
                        $ratioCeiling >= $this->caps->totalBytes
                            ? RejectionCode::TotalSizeExceeded
                            : RejectionCode::CompressionRatioExceeded,
                        basename($this->path),
                    );
                }

                if (fwrite($sink, $chunk) === false) {
                    throw IngestRejected::because(RejectionCode::UnreadableArchive, 'temporary write failed');
                }
            }
        } catch (IngestRejected $rejection) {
            fclose($source);
            fclose($sink);

            throw $rejection;
        }

        fclose($source);
        rewind($sink);

        return $sink;
    }

    /**
     * Split a 512-byte header into its POSIX ustar fields.
     *
     * `a` rather than `A` throughout: `A` strips trailing spaces as well as
     * NULs, and a trailing space is a legal filename character. Trimming it
     * would mean validating `evil.php ` and storing `evil.php`.
     *
     * @return array<string, string>
     */
    private function parseHeader(string $header): array
    {
        $this->assertChecksum($header);

        $fields = unpack(
            'a100name/a8mode/a8uid/a8gid/a12size/a12mtime/a8checksum/a1typeflag/'
            .'a100linkname/a6magic/a2version/a32uname/a32gname/a8devmajor/a8devminor/a155prefix',
            $header,
        );

        if ($fields === false) {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, 'unparseable header');
        }

        /** @var array<string, string> $fields */
        return $fields;
    }

    /**
     * Verify the header checksum, accepting both the unsigned and signed sums.
     *
     * Both are accepted because historic implementations summed the header
     * bytes as signed chars, and a tree produced by one of those is not an
     * attack. Checking at all still matters: it is what stops an arbitrary
     * block in the middle of a stream being read as a header, which is how a
     * sequential parser gets walked off into the data section.
     */
    private function assertChecksum(string $header): void
    {
        $declared = trim(substr($header, 148, 8), " \0");

        if ($declared === '' || preg_match('/^[0-7]+$/', $declared) !== 1) {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, 'header without a checksum');
        }

        $expected = (int) octdec($declared);
        $blanked = substr_replace($header, str_repeat(' ', 8), 148, 8);

        $unsigned = 0;
        $signed = 0;

        for ($i = 0; $i < self::BLOCK; $i++) {
            $byte = ord($blanked[$i]);
            $unsigned += $byte;
            $signed += $byte > 127 ? $byte - 256 : $byte;
        }

        if ($expected !== $unsigned && $expected !== $signed) {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, 'header checksum mismatch');
        }
    }

    /**
     * Read a tar size field, in octal or GNU base-256.
     *
     * Base-256 is signalled by the high bit of the first byte and exists
     * because 12 octal digits cannot express 8 GB. It is parsed rather than
     * refused so that a legitimately huge member produces a size-cap rejection
     * — the honest answer — instead of a parse failure that reads to the author
     * as a corrupt upload.
     */
    private function parseSize(string $raw): int
    {
        if ($raw === '') {
            return 0;
        }

        if ((ord($raw[0]) & 0x80) !== 0) {
            $value = 0;

            for ($i = 0, $length = strlen($raw); $i < $length; $i++) {
                /*
                 * 🛑 Guarded BEFORE the shift, not after. A base-256 size field
                 * is 11 usable bytes and a 64-bit int holds 8, and `<<` on
                 * overflow discards the high bits silently — it can even yield a
                 * negative value, which would sail straight past every `>`
                 * comparison in the caps. Checking the room left is the only
                 * form of this test that can see the overflow at all.
                 */
                if ($value > (PHP_INT_MAX >> 8)) {
                    throw IngestRejected::because(
                        RejectionCode::FileSizeExceeded,
                        detail: 'size field overflows a 64-bit integer',
                    );
                }

                // The high bit of byte 0 is the format flag, not magnitude.
                $value = ($value << 8) | (ord($raw[$i]) & ($i === 0 ? 0x7F : 0xFF));
            }

            return $value;
        }

        $octal = trim($raw, " \0");

        if ($octal === '') {
            return 0;
        }

        if (preg_match('/^[0-7]+$/', $octal) !== 1) {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, 'non-octal size field');
        }

        return (int) octdec($octal);
    }

    /**
     * The `path` record from a pax extended header, if it carries one.
     *
     * Records are `length key=value\n`, repeated, where `length` counts itself.
     * Only `path` is consulted: the rest (mtime, uid, the SCHILY extensions)
     * describe metadata DocUp does not store, and skipping an unknown key is
     * what the format requires.
     */
    private function pathFromPax(string $payload): ?string
    {
        $cursor = 0;
        $length = strlen($payload);
        $path = null;

        while ($cursor < $length) {
            $space = strpos($payload, ' ', $cursor);

            if ($space === false) {
                break;
            }

            $declared = (int) substr($payload, $cursor, $space - $cursor);

            /*
             * 🛑 A non-positive length would not advance the cursor and a record
             * claiming to run past the buffer is malformed. Either one, left
             * unchecked, is an infinite loop on attacker-chosen input — the
             * cheapest denial of service in the whole ingest path.
             */
            if ($declared <= 0 || $cursor + $declared > $length) {
                throw IngestRejected::because(RejectionCode::UnreadableArchive, 'malformed pax record');
            }

            $record = substr($payload, $space + 1, $cursor + $declared - $space - 2);
            $cursor += $declared;

            $equals = strpos($record, '=');

            if ($equals !== false && substr($record, 0, $equals) === 'path') {
                $path = substr($record, $equals + 1);
            }
        }

        return $path;
    }

    /**
     * Rejoin ustar's split name, which is `prefix` + `/` + `name`.
     *
     * The prefix field exists so a ustar header can carry a 255-byte path in
     * two pieces. Ignoring it would mean validating the tail of a path and
     * extracting the whole of it.
     */
    private function joinPrefix(string $prefix, string $name): string
    {
        $prefix = rtrim($prefix, "\0");
        $name = rtrim($name, "\0");

        return $prefix === '' ? $name : $prefix.'/'.$name;
    }

    private function classify(string $typeflag, string $name): EntryType
    {
        return match ($typeflag) {
            // '7' is a contiguous file, which every modern system stores as a
            // plain file. "\0" and '' are pre-ustar writers omitting the field.
            '0', '7', "\0", '' => str_ends_with($name, '/') ? EntryType::Directory : EntryType::File,
            '1' => EntryType::Hardlink,
            '2' => EntryType::Symlink,
            '3' => EntryType::CharacterDevice,
            '4' => EntryType::BlockDevice,
            '5' => EntryType::Directory,
            '6' => EntryType::Fifo,
            // 🛑 Anything unrecognised is Unknown, which EntryType::rejection()
            // refuses. A typeflag this reader has not been taught is not a
            // reason to guess "probably a file".
            default => EntryType::Unknown,
        };
    }

    /** @param  resource  $handle */
    private function skipPadding($handle, int $size): void
    {
        $padding = $this->paddedLength($size) - $size;

        if ($padding > 0) {
            fseek($handle, $padding, SEEK_CUR);
        }
    }

    /** Member data is padded up to the next whole block. */
    private function paddedLength(int $size): int
    {
        return (int) (ceil($size / self::BLOCK) * self::BLOCK);
    }

    /**
     * Tell "a valid empty tar" apart from "not a tar at all".
     *
     * An empty tar is two zero blocks, so a file whose first block is all NULs
     * is empty-but-valid and anything else that yielded no entries was never a
     * tar. Without this, a JPEG uploaded by mistake would publish successfully
     * as a tree of nothing.
     */
    private function endsCleanly(): bool
    {
        $handle = $this->open();

        if (fseek($handle, 0, SEEK_SET) !== 0) {
            return false;
        }

        $block = (string) fread($handle, self::BLOCK);

        return strlen($block) === self::BLOCK && trim($block, "\0") === '';
    }
}
