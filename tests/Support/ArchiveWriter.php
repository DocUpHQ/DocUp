<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Support;

use App\Artifacts\TarArchiveReader;
use ZipArchive;

/**
 * Writes tar and zip archives, including ones no sane tool would produce.
 *
 * 🛑 This exists because the abuse corpus needs hostile fixtures and no library
 * will make them. `PharData` refuses a path containing `..`, and PHP's
 * `ZipArchive` cannot be persuaded to store a hard link. A test that cannot
 * construct the attack cannot prove the defence, so the headers are written by
 * hand here — the same reason {@see TarArchiveReader} parses them
 * by hand.
 *
 * Deliberately NOT in `app/`. Nothing in the product writes a tar, and a
 * class that can emit a zip-slip entry has no business being autoloadable in
 * production.
 */
final class ArchiveWriter
{
    private const BLOCK = 512;

    /** POSIX ustar typeflags, named so the builders below read as prose. */
    public const FILE = '0';

    public const HARDLINK = '1';

    public const SYMLINK = '2';

    public const CHAR_DEVICE = '3';

    public const BLOCK_DEVICE = '4';

    public const DIRECTORY = '5';

    public const FIFO = '6';

    /** @var list<string> complete 512-byte blocks, in order */
    private array $blocks = [];

    /**
     * Append one member.
     *
     * @param  string  $typeflag  one of the constants above
     * @param  string  $linkname  the target, for a link entry
     */
    public function add(
        string $name,
        string $contents = '',
        string $typeflag = self::FILE,
        string $linkname = '',
        int $mode = 0o644,
    ): self {
        /*
         * GNU long-name records, emitted exactly as GNU tar does: an 'L' header
         * whose data is the real name, followed by the member itself carrying a
         * truncated name. The corpus needs this for the 300-byte-filename case,
         * and it is also the smuggling vector TarArchiveReader is written to
         * see through — so the writer has to be able to build it.
         */
        if (strlen($name) > 100) {
            $this->appendHeader('././@LongLink', strlen($name) + 1, 'L', '', 0o644);
            $this->appendData($name."\0");
        }

        $this->appendHeader($name, strlen($contents), $typeflag, $linkname, $mode);

        if ($contents !== '') {
            $this->appendData($contents);
        }

        return $this;
    }

    /** Append a pax extended header carrying `path`, then the member. */
    public function addWithPaxPath(string $name, string $contents = ''): self
    {
        // `length key=value\n`, where length counts itself.
        $record = 'path='.$name."\n";
        $record = (strlen($record) + strlen((string) (strlen($record) + 2)) + 1).' '.$record;

        $this->appendHeader('PaxHeaders/x', strlen($record), 'x', '', 0o644);
        $this->appendData($record);
        $this->appendHeader('smuggled.html', strlen($contents), self::FILE, '', 0o644);

        if ($contents !== '') {
            $this->appendData($contents);
        }

        return $this;
    }

    /** Write the archive, terminator included. */
    public function toTar(string $path): string
    {
        $bytes = implode('', $this->blocks).str_repeat("\0", self::BLOCK * 2);

        if (file_put_contents($path, $bytes) === false) {
            throw new \RuntimeException("Could not write tar to [{$path}].");
        }

        return $path;
    }

    /** Write the archive gzipped, as a build runner would upload it. */
    public function toTarGz(string $path, int $level = 9): string
    {
        $bytes = implode('', $this->blocks).str_repeat("\0", self::BLOCK * 2);
        $compressed = gzencode($bytes, $level);

        if ($compressed === false || file_put_contents($path, $compressed) === false) {
            throw new \RuntimeException("Could not write tar.gz to [{$path}].");
        }

        return $path;
    }

    /**
     * Write a zip instead, with Unix modes preserved.
     *
     * Separate from the tar path because the formats disagree about what they
     * can express: a zip stores a symlink as a member whose **external
     * attributes** carry `S_IFLNK`, and cannot store a hard link at all.
     *
     * @param  array<string, array{0: string, 1: int}>  $members  name => [contents, unix mode]
     */
    public static function zip(string $path, array $members): string
    {
        @unlink($path);
        $zip = new \ZipArchive;

        if ($zip->open($path, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) !== true) {
            throw new \RuntimeException("Could not create zip at [{$path}].");
        }

        foreach ($members as $name => [$contents, $mode]) {
            $zip->addFromString($name, $contents);
            // The high 16 bits are the st_mode an extractor would apply; the
            // low 16 are MS-DOS attributes, which nothing here needs.
            $zip->setExternalAttributesName($name, \ZipArchive::OPSYS_UNIX, $mode << 16);
        }

        $zip->close();

        return $path;
    }

    /**
     * Write a tar of `$count` empty members, streamed rather than buffered.
     *
     * 100,000 headers is 51 MB. Buffering that in {@see self::$blocks} to
     * concatenate it would cost several times that in peak memory for no
     * reason, and the file-count fixture is the one case where the archive is
     * large by design.
     */
    public static function tarWithManyFiles(string $path, int $count): string
    {
        $handle = fopen($path, 'wb');

        if ($handle === false) {
            throw new \RuntimeException("Could not write tar to [{$path}].");
        }

        $writer = new self;
        $writer->appendHeader('html/index.html', 0, self::FILE, '', 0o644);
        fwrite($handle, $writer->blocks[0]);

        for ($i = 0; $i < $count; $i++) {
            $single = new self;
            $single->appendHeader(sprintf('html/p%06d.html', $i), 0, self::FILE, '', 0o644);
            fwrite($handle, $single->blocks[0]);
        }

        fwrite($handle, str_repeat("\0", self::BLOCK * 2));
        fclose($handle);

        return $path;
    }

    /**
     * Build one 512-byte ustar header with a correct checksum.
     *
     * The checksum is computed over the header with its own field blanked to
     * spaces, which is the convention every tar implementation follows, and is
     * what {@see TarArchiveReader::assertChecksum()} verifies.
     */
    private function appendHeader(
        string $name,
        int $size,
        string $typeflag,
        string $linkname,
        int $mode,
    ): void {
        $header = str_pad(substr($name, 0, 100), 100, "\0")
            .sprintf("%07o\0", $mode)
            .sprintf("%07o\0", 0)
            .sprintf("%07o\0", 0)
            .sprintf("%011o\0", $size)
            .sprintf("%011o\0", 0)
            .str_repeat(' ', 8)                         // checksum placeholder
            .$typeflag
            .str_pad(substr($linkname, 0, 100), 100, "\0")
            ."ustar\0"
            .'00'
            .str_pad('docup', 32, "\0")
            .str_pad('docup', 32, "\0")
            .sprintf("%07o\0", 0)
            .sprintf("%07o\0", 0)
            .str_repeat("\0", 155)
            .str_repeat("\0", 12);

        $checksum = 0;

        for ($i = 0; $i < self::BLOCK; $i++) {
            $checksum += ord($header[$i]);
        }

        $this->blocks[] = substr_replace($header, sprintf("%06o\0 ", $checksum), 148, 8);
    }

    /** Append member data, padded to the next whole block. */
    private function appendData(string $contents): void
    {
        $padded = str_pad($contents, (int) (ceil(strlen($contents) / self::BLOCK) * self::BLOCK), "\0");

        foreach (str_split($padded, self::BLOCK) as $block) {
            $this->blocks[] = $block;
        }
    }
}
