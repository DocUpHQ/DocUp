<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

/**
 * One entry as the archive DECLARES it (§8.8.2).
 *
 * 🛑 "Declares" is the important word. These values come from the archive's own
 * headers, which are attacker-supplied: a zip can claim a 10-byte uncompressed
 * size for an entry that expands to a gigabyte. The ingestor uses them to
 * refuse obvious attacks cheaply **before extracting anything** — that is the
 * whole purpose of a compression-ratio cap — and then re-checks the real size
 * while streaming the bytes out, because a header cannot be trusted to be true,
 * only to be a reason to stop early.
 */
final class ArchiveEntry
{
    /**
     * @param  int  $index  position in the archive, used to fetch the entry's
     *                      bytes back from the reader. Positional rather than
     *                      by name because a name is attacker-supplied and need
     *                      not be unique, and looking an entry up by one would
     *                      let a duplicate name decide which bytes get stored.
     */
    public function __construct(
        public readonly int $index,
        public readonly string $name,
        public readonly EntryType $type,
        public readonly int $declaredSize,
        public readonly int $compressedSize,
    ) {}

    /**
     * Uncompressed:compressed, for the §8.8.2 ratio cap.
     *
     * A zero compressed size for a non-empty entry is reported as INF rather
     * than special-cased: that shape IS the bomb, and INF compares against the
     * cap correctly with no extra branch at the call site.
     */
    public function compressionRatio(): float
    {
        if ($this->declaredSize === 0) {
            return 0.0;
        }

        if ($this->compressedSize <= 0) {
            return INF;
        }

        return $this->declaredSize / $this->compressedSize;
    }
}
