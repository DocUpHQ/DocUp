<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

use App\Builds\PublishSource;

/**
 * A POSIX ustar writer, for the one thing that needs to produce an archive
 * rather than read one.
 *
 * §8.5.19's fragment cache hits with output that is already in the artifact
 * store, and §8.21.6 insists there is exactly one way into that store: "the
 * built-in runner MUST be implemented as the **first consumer** of this path,
 * not a privileged special case". So a cache hit re-enters through the same
 * {@see PublishSource} every upload uses, which means it needs an
 * archive — and the alternative, a second write path that skips ingest, is
 * the privileged special case that requirement exists to forbid.
 *
 * 🛑 **Written by hand rather than with `PharData`.** `PharData` is part of
 * the phar extension, which hardened PHP builds disable and which operators
 * are routinely told to disable; a core publishing path must not depend on
 * it. Sixty lines of ustar is a smaller liability than a deployment where
 * republishing from the cache is unavailable for a reason nobody can see.
 *
 * 🛑 **Deterministic.** Fixed mtime, fixed uid/gid, sorted entries — so two
 * archives of the same tree are byte-identical. {@see TarArchiveReader} is
 * what reads these back, which makes the existing reader the writer's test.
 */
final class TarArchiveWriter
{
    private const BLOCK = 512;

    /**
     * 🛑 A fixed timestamp, not `time()`. The archive is an intermediate on
     * the way back into the store; giving it the clock would make two
     * republishes of one unchanged tree differ, which is exactly the
     * property §18.13 measures the fragment cache against.
     */
    private const MTIME = 315532800;

    /** @var resource */
    private $handle;

    private function __construct(string $path)
    {
        $handle = fopen($path, 'wb');

        if ($handle === false) {
            throw new \RuntimeException('could not open '.$path.' for writing');
        }

        $this->handle = $handle;
    }

    /**
     * Write every entry to a new archive at `$path`.
     *
     * @param  iterable<string, string>  $entries  relative path => contents
     */
    public static function write(string $path, iterable $entries): void
    {
        $writer = new self($path);

        try {
            foreach ($entries as $name => $contents) {
                $writer->add($name, $contents);
            }

            $writer->finish();
        } finally {
            fclose($writer->handle);
        }
    }

    private function add(string $name, string $contents): void
    {
        [$prefix, $suffix] = self::split($name);

        $header = pack('a100', $suffix)
            .pack('a8', '0000644')           // mode: readable, never executable
            .pack('a8', '0000000')           // uid 0: the archive carries no identity
            .pack('a8', '0000000')           // gid 0
            .pack('a12', sprintf('%011o', strlen($contents)))
            .pack('a12', sprintf('%011o', self::MTIME))
            .pack('a8', str_repeat(' ', 8))  // checksum, computed over spaces then filled
            .pack('a1', '0')                 // typeflag: a regular file
            .pack('a100', '')                // linkname
            .pack('a6', 'ustar')
            .pack('a2', '00')
            .pack('a32', '')                 // uname
            .pack('a32', '')                 // gname
            .pack('a8', '')                  // devmajor
            .pack('a8', '')                  // devminor
            .pack('a155', $prefix)
            .pack('a12', '');

        $checksum = 0;

        for ($i = 0; $i < self::BLOCK; $i++) {
            $checksum += ord($header[$i]);
        }

        // The checksum field is six octal digits, a NUL and a space — the
        // one field in the format whose padding is not simply NUL, and the
        // usual reason a hand-written tar is rejected by GNU tar.
        $header = substr_replace($header, pack('a8', sprintf('%06o', $checksum)."\0 "), 148, 8);

        fwrite($this->handle, $header);
        fwrite($this->handle, $contents);

        $remainder = strlen($contents) % self::BLOCK;

        if ($remainder !== 0) {
            fwrite($this->handle, str_repeat("\0", self::BLOCK - $remainder));
        }
    }

    /** Two zero blocks: the end-of-archive marker every reader looks for. */
    private function finish(): void
    {
        fwrite($this->handle, str_repeat("\0", self::BLOCK * 2));
    }

    /**
     * ustar splits a long name into a 155-byte prefix and a 100-byte suffix,
     * at a `/`.
     *
     * @return array{0: string,1: string}
     */
    private static function split(string $name): array
    {
        $name = ltrim($name, '/');

        if (strlen($name) <= 100) {
            return ['', $name];
        }

        /*
         * The suffix must be at most 100 bytes, so the split cannot be
         * earlier than `len - 101`; the prefix must be at most 155, so it
         * cannot be later. Taking the FIRST slash at or after the lower
         * bound gives the shortest prefix that satisfies both, which is the
         * split most likely to fit.
         */
        $cut = strpos($name, '/', max(0, strlen($name) - 101));

        if ($cut === false || $cut > 155) {
            /*
             * Refused rather than truncated. A truncated path in an archive
             * is a file published at the wrong URL, which is worse than a
             * build that stops and says the path is too long.
             */
            throw new \RuntimeException('path too long for a ustar archive: '.$name);
        }

        return [substr($name, 0, $cut), substr($name, $cut + 1)];
    }
}
