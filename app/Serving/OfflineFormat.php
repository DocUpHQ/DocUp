<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

use App\Artifacts\ArtifactIngestor;

/**
 * §8.4.5's three offline formats, as the download URL names them.
 *
 * 🛑 `html` is deliberately absent. It is the served tree, not a download:
 * admitting it here would make `/_/downloads/en/latest/html` a URL that either
 * 404s confusingly or hands a reader one arbitrary file out of a site. The
 * zipped form of that tree is `htmlzip`, which is a real download and is here.
 *
 * 🛑 The enum is the **allowlist**. A format arrives as a URL segment from an
 * unauthenticated reader, and it decides both a storage path and a filename
 * extension — `from()` on an unknown value throws, `tryFrom()` returns null,
 * and the controller 404s. There is no path by which a reader-supplied string
 * reaches a storage key.
 */
enum OfflineFormat: string
{
    case Pdf = 'pdf';
    case Epub = 'epub';
    case HtmlZip = 'htmlzip';

    /**
     * The extension the stored leaf and the download filename both carry.
     *
     * 🛑 `htmlzip` is stored and downloaded as `.zip`. The directory names
     * the format and the extension names the media type; they are different
     * things, and `document.htmlzip` is a file no operating system would
     * know how to open.
     */
    public function extension(): string
    {
        return match ($this) {
            self::HtmlZip => 'zip',
            default => $this->value,
        };
    }

    /**
     * The path inside the build's manifest, matching
     * {@see ArtifactIngestor::offlineLeafFor()}.
     *
     * Both sides derive it from the format rather than sharing a constant
     * string, and a test asserts the two agree — a shared literal would be
     * one edit away from a download that 404s because ingest renamed the file
     * and serving did not.
     */
    public function manifestPath(): string
    {
        return $this->value.'/document.'.$this->extension();
    }

    /** The §8.9.11 content type for this format's stored object. */
    public function contentType(): string
    {
        return match ($this) {
            self::Pdf => 'application/pdf',
            self::Epub => 'application/epub+zip',
            self::HtmlZip => 'application/zip',
        };
    }

    /** @return list<string> */
    public static function values(): array
    {
        return array_map(static fn (self $case): string => $case->value, self::cases());
    }
}
