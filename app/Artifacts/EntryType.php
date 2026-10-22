<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

/**
 * What kind of thing an archive entry is (§8.8.2).
 *
 * 🛑 §8.8.2 rejects symlinks, hardlinks, device and FIFO entries, so the
 * ingestor needs to tell them apart — and must be able to say WHICH, because
 * the exit criteria require a distinct stable error code for each.
 *
 * The distinction is also why DocUp reads tar headers itself rather than using
 * `PharData`: a hard link exists only in tar (typeflag `1`), and the
 * convenience wrappers normalise typeflags away. An extractor that cannot see
 * the difference between a file and a hard link cannot refuse one.
 */
enum EntryType: string
{
    case File = 'file';
    case Directory = 'directory';
    case Symlink = 'symlink';
    case Hardlink = 'hardlink';
    case CharacterDevice = 'character_device';
    case BlockDevice = 'block_device';
    case Fifo = 'fifo';

    /** Anything the reader could not classify. Refused on principle. */
    case Unknown = 'unknown';

    /**
     * The §8.8.2 rejection this type attracts, or null when it is permitted.
     *
     * Asked of the type rather than decided at the call site, so a type added
     * later cannot default to "allowed" by being forgotten — {@see self::Unknown}
     * is the catch-all and it is refused.
     */
    public function rejection(): ?RejectionCode
    {
        return match ($this) {
            self::File, self::Directory => null,
            self::Symlink => RejectionCode::SymlinkRejected,
            self::Hardlink => RejectionCode::HardlinkRejected,
            self::CharacterDevice, self::BlockDevice, self::Fifo, self::Unknown => RejectionCode::UnsupportedEntryType,
        };
    }
}
