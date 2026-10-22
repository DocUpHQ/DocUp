<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

/**
 * Stable identifiers for every §8.8.2 and §8.4.5 rejection.
 *
 * 🛑 **Stable** is the operative word, and §8.19.15 requires it: these strings
 * reach build logs, the API, operator alerts and runbooks. A reworded
 * identifier is a broken alert at somebody's 3am, so the values here are part
 * of the §8.1.11 public contract and may not be edited — only added to.
 *
 * 🛑 **The values are the abuse corpus's, not this file's invention.** Phase 00
 * authored `tests/Fixtures/AbuseCorpus/corpus.json` *before* any production
 * code existed, precisely so that the implementation would be measured against
 * a commitment rather than against itself, and it names the expected identifier
 * for twelve hostile archives. §8.19.15's own worked example —
 * `contract.multiple_pdf_files` — is one of them. Every value below either
 * comes from that file or follows its spelling.
 *
 * On the `contract` class rather than `rejected`: §8.19.15 offers both, and a
 * malformed tree violates §8.4.5's **output contract**. DocUp cannot know
 * whether a `.user.ini` was planted or emitted by a careless template, and the
 * author needs the same answer either way — "this build produced something that
 * will not be published, and here is exactly what". Keeping `rejected` for
 * requests refused before a build runs leaves the two readable apart in a log.
 *
 * Phase 03's exit criteria require a **distinct** code for six cases — zip-slip,
 * an absolute symlink, a hardlink, a 100,000-file tree, a 101:1 compression
 * ratio and a planted `.user.ini`. Distinctness is the point: one generic
 * identifier would leave an author guessing which of six very different
 * problems they have.
 */
enum RejectionCode: string
{
    // ------------------------------------------------------------- path shape

    /**
     * A `..` or `.` segment, i.e. zip-slip. The archetypal archive attack: an
     * entry named `../../etc/cron.d/x` escapes the extraction root entirely.
     *
     * `.` is refused alongside `..` because a segment that does not mean itself
     * cannot round-trip. The manifest would record `a/./b` while the serving
     * edge resolved `a/b`, and §8.4.18's manifest exists precisely so the edge
     * can answer without a storage probe — a manifest whose paths are not the
     * paths being served answers wrongly, and does it silently.
     */
    case PathEscapesRoot = 'contract.path_escapes_root';

    /** A leading `/` or a Windows drive letter. */
    case AbsolutePath = 'contract.absolute_path';

    /**
     * A backslash anywhere in the name.
     *
     * Refused rather than normalised, because `a\..\..\b` means different
     * things to different extractors, and a path whose meaning depends on its
     * reader cannot be validated once.
     */
    case BackslashInName = 'contract.backslash_in_name';

    /**
     * NUL, any C0 control character, or DEL.
     *
     * NUL truncates a name in any C library that sees it, so `safe.html\0.php`
     * is checked as one name and written as another.
     */
    case ControlCharacterInName = 'contract.control_character_in_name';

    /** A path component over 255 bytes, or a path too long to store. */
    case FilenameTooLong = 'contract.filename_too_long';

    // ------------------------------------------------------------- entry kind

    /**
     * A symbolic link.
     *
     * Refused whatever it points at, not merely when it escapes: a link that
     * resolves inside the tree today resolves wherever its target later moves,
     * and the serving edge follows links with the web server's privileges
     * rather than the application's.
     */
    case SymlinkRejected = 'contract.symlink_rejected';

    /**
     * A hard link.
     *
     * Worse than a symlink in one specific way: there is no target to inspect,
     * because a hard link *is* the file. One pointing outside the tree makes
     * that file part of the published output with nothing in the tree to
     * indicate it.
     */
    case HardlinkRejected = 'contract.hardlink_rejected';

    /** A block device, character device, FIFO, socket or unrecognised type. */
    case UnsupportedEntryType = 'contract.unsupported_entry_type';

    // ---------------------------------------------------------------- filename

    /**
     * 🛑 `.htaccess`, `.user.ini`, `web.config`, or a PHP-handler extension.
     *
     * §8.8.2 states the reason plainly: "`.user.ini` planted in a build output
     * is code execution if the storage root is ever a PHP document root." The
     * artifact root is not a document root today, and DocUp cannot promise it
     * never will be on an installation it does not control — one reverse proxy
     * misconfigured, or one operator serving the directory directly to debug
     * something at 2am.
     */
    case ReservedFilename = 'contract.reserved_filename';

    // -------------------------------------------------------- output contract

    /** §8.4.5: `html/index.html` is mandatory. */
    case MissingHtmlIndex = 'contract.missing_html_index';

    /**
     * §8.4.5: each offline format directory holds exactly one file.
     *
     * Three identifiers rather than one with a parameter, because §8.19.15's
     * worked example is literally `contract.multiple_pdf_files` — and an
     * identifier that varies is not an identifier. Nobody can alert on
     * `contract.multiple_{format}_files`.
     */
    case MultiplePdfFiles = 'contract.multiple_pdf_files';

    case MultipleEpubFiles = 'contract.multiple_epub_files';

    case MultipleHtmlzipFiles = 'contract.multiple_htmlzip_files';

    /**
     * A top-level entry that is not one of §8.4.5's format directories.
     *
     * Refused rather than ignored. "anything written to
     * `$DOCUP_OUTPUT/{html,pdf,epub,htmlzip}/` is published" could be read as
     * licence to drop the rest silently, but an author whose files vanish
     * without a word has no way to find out why — and a build that quietly
     * publishes less than it produced is the kind of success that gets noticed
     * by a reader rather than by its author.
     */
    case UnknownOutputDirectory = 'contract.unknown_output_directory';

    // -------------------------------------------------------------------- caps

    /** More entries than the configured ceiling (default 50,000). */
    case FileCountExceeded = 'contract.file_count_exceeded';

    /** Uncompressed total above the ceiling (default 5 GB). */
    case TotalSizeExceeded = 'contract.total_size_exceeded';

    /** One file above the per-file ceiling (default 1 GB). */
    case FileSizeExceeded = 'contract.file_size_exceeded';

    /**
     * Uncompressed:compressed above the ceiling (default 100:1) — a zip bomb.
     *
     * Checked from the archive's declared sizes **before** anything is written,
     * and again during decompression, because the whole point of a bomb is that
     * discovering it by extracting is already the damage.
     */
    case CompressionRatioExceeded = 'contract.compression_ratio_exceeded';

    // ------------------------------------------------------------------- other

    /** The upload could not be opened, or is not a supported archive format. */
    case UnreadableArchive = 'contract.unreadable_archive';

    /**
     * Two entries with the same name.
     *
     * 🛑 Not in §8.8.2's list — see the amendment proposed in the Phase 03
     * build-log entry. It belongs there because §8.8.1's store is
     * **write-once**, so a duplicate has no representation at all. Tar's
     * last-one-wins convention would have the manifest record one entry's
     * sha256 while the store held the other's bytes, breaking the strong ETag
     * and the integrity check in a single move. Refusing is the only outcome
     * that keeps the manifest true.
     */
    case DuplicateEntry = 'contract.duplicate_entry';

    /** §8.8.10: a storage or count quota would be breached. */
    case QuotaExceeded = 'contract.quota_exceeded';

    /**
     * The identifier for "this offline format directory holds more than one
     * file", given the format.
     *
     * @throws \ValueError when the format has no such identifier, which means a
     *                     format reached §10.3 without one being added here
     */
    public static function multipleFilesFor(string $format): self
    {
        return match ($format) {
            'pdf' => self::MultiplePdfFiles,
            'epub' => self::MultipleEpubFiles,
            'htmlzip' => self::MultipleHtmlzipFiles,
            default => throw new \ValueError("No multiple-files identifier for format [{$format}]."),
        };
    }

    /**
     * The §8.19.15 failure class this code belongs to.
     *
     * Derived from the identifier rather than stored separately, so the two can
     * never disagree — a build row carrying `failure_class = 'rejected'` beside
     * `failure_identifier = 'contract.quota_exceeded'` would be a lie that every
     * downstream alert inherits.
     */
    public function failureClass(): string
    {
        return explode('.', $this->value, 2)[0];
    }

    /** A one-line explanation for the build log and the API response. */
    public function describe(): string
    {
        return match ($this) {
            self::PathEscapesRoot => 'An entry name contains a "." or ".." segment, which would escape the '
                .'extraction root.',
            self::AbsolutePath => 'An entry name is an absolute path.',
            self::BackslashInName => 'An entry name contains a backslash, whose meaning differs between extractors.',
            self::ControlCharacterInName => 'An entry name contains a NUL or control character.',
            self::FilenameTooLong => 'A path component exceeds 255 bytes, or the path is too long to store.',
            self::SymlinkRejected => 'The tree contains a symbolic link. Artifacts must be plain files and '
                .'directories.',
            self::HardlinkRejected => 'The tree contains a hard link.',
            self::UnsupportedEntryType => 'The tree contains a device, FIFO or socket entry.',
            self::ReservedFilename => 'The tree contains a filename that can alter server behaviour '
                .'(.htaccess, .user.ini, web.config or a PHP handler extension).',
            self::MissingHtmlIndex => 'The build output has no html/index.html, which the output contract '
                .'makes mandatory.',
            self::MultiplePdfFiles => 'The pdf output directory must contain exactly one file.',
            self::MultipleEpubFiles => 'The epub output directory must contain exactly one file.',
            self::MultipleHtmlzipFiles => 'The htmlzip output directory must contain exactly one file.',
            self::UnknownOutputDirectory => 'The build output contains an entry outside html/, pdf/, epub/ '
                .'and htmlzip/.',
            self::FileCountExceeded => 'The tree contains more files than this installation allows.',
            self::TotalSizeExceeded => 'The uncompressed tree is larger than this installation allows.',
            self::FileSizeExceeded => 'A single file is larger than this installation allows.',
            self::CompressionRatioExceeded => 'The upload decompresses by more than the allowed ratio.',
            self::UnreadableArchive => 'The upload could not be read as a supported archive.',
            self::DuplicateEntry => 'Two entries in the archive have the same name.',
            self::QuotaExceeded => 'Publishing this tree would exceed a quota for this organisation.',
        };
    }
}
