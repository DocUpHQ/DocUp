<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

use App\Artifacts\Exceptions\IngestRejected;

/**
 * Reads a zip, preserving the Unix mode so a symlink can be refused.
 *
 * 🛑 The whole reason this class touches `getExternalAttributesIndex()` rather
 * than just `statIndex()`: a zip stores a symlink as an ordinary member whose
 * **external attributes** carry `S_IFLNK`, with the link target as the member's
 * contents. `statIndex()` reports it as a file of 11 bytes. An extractor that
 * only looks at `statIndex()` therefore cannot see a symlink at all, and
 * §8.8.2 requires refusing one — so the mode bits are not an optional nicety
 * here, they are the only evidence that exists.
 *
 * A zip cannot express a hard link, a device or a FIFO, so those cases arrive
 * as tar; see {@see TarArchiveReader}.
 */
final class ZipArchiveReader implements ArchiveReader
{
    private ?\ZipArchive $zip = null;

    /** @var list<ArchiveEntry>|null */
    private ?array $entries = null;

    public function __construct(
        private readonly string $path,
        private readonly IngestCaps $caps,
    ) {}

    public function entries(): array
    {
        if ($this->entries !== null) {
            return $this->entries;
        }

        $zip = $this->open();

        /*
         * 🛑 Checked before the loop, from the central directory, which libzip
         * has already parsed. Unlike tar there is no need to walk the archive
         * to learn the count, so the cheapest possible refusal is also the
         * earliest one: a 100,000-entry zip costs one integer comparison.
         */
        if ($zip->numFiles > $this->caps->files) {
            throw IngestRejected::because(
                RejectionCode::FileCountExceeded,
                detail: $zip->numFiles.' entries, cap is '.$this->caps->files,
            );
        }

        $entries = [];

        for ($index = 0; $index < $zip->numFiles; $index++) {
            $stat = $zip->statIndex($index);

            if ($stat === false) {
                throw IngestRejected::because(RejectionCode::UnreadableArchive, "entry #{$index}");
            }

            /*
             * Raw name, not a normalised one. Normalising here would defeat the
             * point — `..` would be resolved away before the check that exists
             * to find it. The ingestor sees exactly what the archive claims.
             */
            $name = (string) $stat['name'];

            $entries[] = new ArchiveEntry(
                index: $index,
                name: $name,
                type: $this->classify($zip, $index, $name),
                declaredSize: (int) $stat['size'],
                compressedSize: (int) $stat['comp_size'],
            );
        }

        return $this->entries = $entries;
    }

    public function stream(ArchiveEntry $entry)
    {
        $stream = $this->open()->getStreamIndex($entry->index);

        if ($stream === false) {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, $entry->name);
        }

        return $stream;
    }

    public function archiveBytes(): int
    {
        $size = @filesize($this->path);

        return $size === false ? 0 : $size;
    }

    public function format(): string
    {
        return 'zip';
    }

    public function close(): void
    {
        $this->zip?->close();
        $this->zip = null;
    }

    private function open(): \ZipArchive
    {
        if ($this->zip instanceof \ZipArchive) {
            return $this->zip;
        }

        $zip = new \ZipArchive;

        /*
         * RDONLY and CHECKCONS together. CHECKCONS makes libzip verify that the
         * central directory agrees with the local file headers, which is the
         * check that catches a zip whose directory advertises `index.html`
         * while the local header at that offset says something else. Without
         * it, validation and extraction can legitimately disagree about what
         * an entry is called.
         */
        if ($zip->open($this->path, \ZipArchive::RDONLY | \ZipArchive::CHECKCONS) !== true) {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, basename($this->path));
        }

        return $this->zip = $zip;
    }

    /**
     * What kind of entry this is, from the Unix mode in the external attributes.
     *
     * Falls back to directory-by-trailing-slash and otherwise to a plain file,
     * which is correct for a zip written by a Windows tool that stores no Unix
     * mode at all: such a zip cannot contain a link, because the format carries
     * nowhere to say so.
     */
    private function classify(\ZipArchive $zip, int $index, string $name): EntryType
    {
        if (str_ends_with($name, '/')) {
            return EntryType::Directory;
        }

        $opsys = 0;
        $attributes = 0;

        if ($zip->getExternalAttributesIndex($index, $opsys, $attributes) === false) {
            return EntryType::File;
        }

        if ($opsys !== \ZipArchive::OPSYS_UNIX) {
            return EntryType::File;
        }

        // The high 16 bits of the external attributes are the st_mode an
        // extractor would chmod to; the low 16 are MS-DOS attributes.
        $mode = ($attributes >> 16) & 0xFFFF;

        return match ($mode & 0xF000) {
            0xA000 => EntryType::Symlink,
            0x4000 => EntryType::Directory,
            0x1000 => EntryType::Fifo,
            0x2000 => EntryType::CharacterDevice,
            0x6000 => EntryType::BlockDevice,
            0xC000 => EntryType::Unknown,   // S_IFSOCK
            default => EntryType::File,
        };
    }
}
