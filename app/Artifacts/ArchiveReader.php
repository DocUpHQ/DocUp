<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

/**
 * Enumerate an uploaded archive without extracting it (§8.8.2).
 *
 * 🛑 The separation this interface exists for: §8.8.2 requires DocUp to reject
 * a malicious tree, and a rejection is only a defence if it happens **before**
 * the bytes land. So reading the table of contents and reading an entry's bytes
 * are two operations, and {@see ArtifactIngestor} performs all of the first
 * before any of the second. An extractor that validates as it writes has
 * already written the file that fails validation.
 *
 * Implementations never extract to a path. They hand back a stream and the
 * ingestor chooses the key, which is why no entry name ever reaches a
 * filesystem call: {@see ArtifactStore::keyFor()} builds the key from a build
 * id, and the entry name is only ever a manifest value and a relative suffix.
 */
interface ArchiveReader
{
    /**
     * Every entry, in archive order, as the headers declare them.
     *
     * @return list<ArchiveEntry>
     *
     * @throws Exceptions\IngestRejected when the archive cannot be parsed
     */
    public function entries(): array;

    /**
     * The entry's bytes as a read-only stream.
     *
     * A stream rather than a string because the per-file cap is 1 GB by default
     * and `file_get_contents` on a 1 GB entry is how one upload exhausts a
     * worker's memory limit and takes the queue with it.
     *
     * @return resource
     *
     * @throws Exceptions\IngestRejected when the entry's bytes cannot be read
     */
    public function stream(ArchiveEntry $entry);

    /**
     * Bytes the archive occupies on disk, for the whole-archive ratio check.
     *
     * Needed because a tar has no per-entry compressed size: the compression is
     * applied to the stream, not to each member. Without this, a 40 KB
     * `.tar.gz` expanding to 5 GB would pass a per-entry check that saw a
     * 1:1 ratio on every member.
     */
    public function archiveBytes(): int;

    /** The format name, for build provenance and error messages. */
    public function format(): string;

    /** Release handles and temporary files. Safe to call twice. */
    public function close(): void;
}
