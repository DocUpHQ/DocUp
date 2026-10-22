<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

use App\Artifacts\Exceptions\IngestRejected;

/**
 * Picks an {@see ArchiveReader} by inspecting the file's leading bytes.
 *
 * 🛑 **By content, never by filename.** The uploaded name is attacker-supplied
 * and the two formats are not interchangeable: tar can express a hard link and
 * zip cannot, so a tar presented as `tree.zip` and dispatched on its extension
 * would be handed to {@see ZipArchiveReader}, fail to parse, and — depending on
 * how generously the error were handled — be reported as a corrupt upload
 * rather than as the probe it is. Sniffing the magic bytes means the reader
 * that runs is the reader for the format that is actually there.
 */
final class ArchiveReaderFactory
{
    /**
     * Open an uploaded archive for enumeration.
     *
     * @throws IngestRejected when the file is not a supported archive
     */
    public static function open(string $path, IngestCaps $caps): ArchiveReader
    {
        if (! is_file($path) || ! is_readable($path)) {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, detail: 'not a readable file');
        }

        $handle = fopen($path, 'rb');

        if ($handle === false) {
            throw IngestRejected::because(RejectionCode::UnreadableArchive, detail: 'could not be opened');
        }

        // 263 bytes reaches past ustar's magic at offset 257, which is the
        // deepest signature any supported format puts its marker at.
        $head = (string) fread($handle, 263);
        fclose($handle);

        return match (true) {
            self::isZip($head) => new ZipArchiveReader($path, $caps),
            self::isGzip($head) => new TarArchiveReader($path, compressed: true, caps: $caps),
            self::isTar($head) => new TarArchiveReader($path, compressed: false, caps: $caps),
            default => throw IngestRejected::because(
                RejectionCode::UnreadableArchive,
                detail: 'not a zip, tar or gzipped tar',
            ),
        };
    }

    /**
     * `PK\x03\x04`, or the two sentinels a legal zip may begin with instead.
     *
     * `PK\x05\x06` is an archive with no members and `PK\x07\x08` is a spanned
     * one. Both are recognised so they reach {@see ZipArchiveReader}, where
     * libzip gives a precise answer, rather than being dismissed here as "not
     * an archive" — which would tell an author with an empty build output that
     * their upload was corrupt.
     */
    private static function isZip(string $head): bool
    {
        return str_starts_with($head, "PK\x03\x04")
            || str_starts_with($head, "PK\x05\x06")
            || str_starts_with($head, "PK\x07\x08");
    }

    private static function isGzip(string $head): bool
    {
        return str_starts_with($head, "\x1f\x8b");
    }

    /**
     * `ustar` at offset 257, in either the POSIX or the GNU spelling.
     *
     * A pre-ustar tar carries no magic at all and is therefore not accepted.
     * That is deliberate: without the magic there is nothing to tell a tar
     * apart from arbitrary bytes except a checksum that could be forged, and
     * every writer in use for the last thirty years emits it.
     */
    private static function isTar(string $head): bool
    {
        if (strlen($head) < 263) {
            return false;
        }

        $magic = substr($head, 257, 6);

        return $magic === "ustar\0" || $magic === 'ustar ';
    }
}
