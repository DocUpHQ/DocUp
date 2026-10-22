<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Support;

use App\Artifacts\ArtifactIngestor;
use App\Artifacts\IngestCaps;

/**
 * The abuse corpus's `archive` fixtures, built in PHP.
 *
 * 🛑 One method per `builder` name in `tests/Fixtures/AbuseCorpus/corpus.json`,
 * and `ArtifactIngestorTest` fails if the corpus names one that is missing
 * here. That test is the reason this file cannot quietly fall behind: the
 * corpus is append-only evidence (§9.4) and a case with no fixture is a case
 * that silently stops running — which is worse than no case at all, because the
 * suite still reports it green.
 *
 * Phase 00 wrote `archives/build_archives.py` for the same fixtures. These are
 * in PHP because neither the container nor CI has a Python interpreter, so the
 * Python version cannot run where it matters; the README records which is which.
 *
 * 🛑 Every archive here is hostile by design. Never extract one with a stock
 * extractor. They exist to be refused.
 */
final class HostileArchives
{
    private const HTML = "<!doctype html><html><head><title>ok</title></head><body>ok</body></html>\n";

    /*
     * The valid tree's other two members, as constants rather than literals at
     * each call site. They were literals once, the zip and tar builders drifted
     * apart by fifteen bytes, and "both readers see the same tree" then failed
     * for a reason that had nothing to do with either reader.
     */
    private const GUIDE = "<!doctype html><p>guide</p>\n";

    private const CSS = "body{color:#222}\n";

    /**
     * Build the named fixture into `$directory` and return its path.
     *
     * @throws \RuntimeException when the corpus names a builder that does not exist
     */
    public static function build(string $builder, string $directory): string
    {
        $method = str_replace(' ', '', ucwords(str_replace('_', ' ', $builder)));
        $method = 'build'.$method;

        if (! method_exists(self::class, $method)) {
            throw new \RuntimeException(
                "The abuse corpus names builder [{$builder}], which has no [{$method}] here. "
                .'Add it — a corpus case without a fixture stops running and still reports green.'
            );
        }

        if (! is_dir($directory) && ! mkdir($directory, 0o755, true)) {
            throw new \RuntimeException("Could not create fixture directory [{$directory}].");
        }

        /** @var string */
        return self::{$method}(rtrim($directory, '/\\').'/'.$builder);
    }

    // ------------------------------------------------------------- valid trees

    /** The happy path: §17's "three-file tree", for the exit criteria. */
    public static function buildValidThreeFileTree(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('html/guide.html', self::GUIDE)
            ->add('html/assets/site.css', self::CSS)
            ->toTarGz($stem.'.tar.gz');
    }

    /**
     * The same tree as `tar -C "$DOCUP_OUTPUT" -czf out.tar.gz .` emits it.
     *
     * Valid, and the reason {@see ArtifactIngestor} strips one
     * leading `./`: this is the most natural command a runner would use, and
     * refusing it would fail the common case to defend against nothing.
     */
    public static function buildDotPrefixedTree(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('./', '', ArchiveWriter::DIRECTORY)
            ->add('./html/', '', ArchiveWriter::DIRECTORY)
            ->add('./html/index.html', self::HTML)
            ->add('./html/guide.html', "<p>guide</p>\n")
            ->toTarGz($stem.'.tar.gz');
    }

    /** A valid tree in zip form, to prove both readers accept the same trees. */
    public static function buildValidZipTree(string $stem): string
    {
        return ArchiveWriter::zip($stem.'.zip', [
            'html/index.html' => [self::HTML, 0o100644],
            'html/guide.html' => [self::GUIDE, 0o100644],
            'html/assets/site.css' => [self::CSS, 0o100644],
        ]);
    }

    // ------------------------------------------------------------- path shape

    /** A member whose path escapes the extraction root. */
    public static function buildZipSlip(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('../../../../etc/cron.d/pwned', "* * * * * root id\n")
            ->toTarGz($stem.'.tar.gz');
    }

    /** A `.` segment mid-path, which would not round-trip to the served path. */
    public static function buildDotSegmentInMiddle(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('html/./guide.html', "<p>guide</p>\n")
            ->toTarGz($stem.'.tar.gz');
    }

    public static function buildAbsolutePathEntry(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('/etc/cron.d/pwned', "* * * * * root id\n")
            ->toTarGz($stem.'.tar.gz');
    }

    public static function buildBackslashName(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('html\\..\\..\\windows\\system32\\x.html', "<p>x</p>\n")
            ->toTarGz($stem.'.tar.gz');
    }

    /** `safe.html\0.php`: validated as one name, written as another. */
    public static function buildNulInName(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add("html/safe.html\0.x", "<p>x</p>\n")
            ->toTarGz($stem.'.tar.gz');
    }

    public static function buildOverlongName(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('html/'.str_repeat('a', 300).'.html', self::HTML)
            ->toTarGz($stem.'.tar.gz');
    }

    /**
     * A traversal hidden in a pax `path` record.
     *
     * 🛑 The header field reads `smuggled.html`; the real name is in the
     * preceding extended header. A reader that trusts the 100-byte field sees
     * nothing wrong with this archive.
     */
    public static function buildPaxSmuggledTraversal(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->addWithPaxPath('../../../../etc/cron.d/pwned', "* * * * * root id\n")
            ->toTarGz($stem.'.tar.gz');
    }

    // ------------------------------------------------------------- entry kind

    public static function buildAbsoluteSymlink(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('html/passwd', '', ArchiveWriter::SYMLINK, '/etc/passwd', 0o777)
            ->toTarGz($stem.'.tar.gz');
    }

    public static function buildRelativeSymlinkEscape(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('html/escape', '', ArchiveWriter::SYMLINK, '../../../../etc/passwd', 0o777)
            ->toTarGz($stem.'.tar.gz');
    }

    public static function buildHardlink(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('html/hard', '', ArchiveWriter::HARDLINK, '/etc/passwd')
            ->toTarGz($stem.'.tar.gz');
    }

    public static function buildDeviceNode(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('html/null', '', ArchiveWriter::CHAR_DEVICE, '', 0o666)
            ->toTarGz($stem.'.tar.gz');
    }

    public static function buildFifoEntry(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('html/pipe', '', ArchiveWriter::FIFO, '', 0o666)
            ->toTarGz($stem.'.tar.gz');
    }

    /** A symlink in zip form, where the evidence is the external attributes. */
    public static function buildZipSymlink(string $stem): string
    {
        return ArchiveWriter::zip($stem.'.zip', [
            'html/index.html' => [self::HTML, 0o100644],
            // S_IFLNK | 0777. The member's contents are the link target, which
            // is how a zip stores a symlink at all.
            'html/passwd' => ['/etc/passwd', 0o120777],
        ]);
    }

    // ---------------------------------------------------------------- filename

    public static function buildReservedUserIni(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('html/.user.ini', "auto_prepend_file=/tmp/x.php\n")
            ->toTarGz($stem.'.tar.gz');
    }

    public static function buildReservedHtaccess(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('html/.htaccess', "AddHandler application/x-httpd-php .html\n")
            ->toTarGz($stem.'.tar.gz');
    }

    public static function buildPhpFile(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('html/shell.php', "<?php system(\$_GET['c']); ?>\n")
            ->toTarGz($stem.'.tar.gz');
    }

    // ------------------------------------------------------- output contract

    public static function buildMissingIndex(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/guide.html', self::HTML)
            ->toTarGz($stem.'.tar.gz');
    }

    public static function buildTwoPdfFiles(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('pdf/one.pdf', "%PDF-1.7\n")
            ->add('pdf/two.pdf', "%PDF-1.7\n")
            ->toTarGz($stem.'.tar.gz');
    }

    public static function buildStrayTopLevelFile(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('README.txt', "not an output directory\n")
            ->toTarGz($stem.'.tar.gz');
    }

    // -------------------------------------------------------------------- caps

    /**
     * ~8 MB of zeroes, which gzip reduces to a few kilobytes.
     *
     * Small enough to build in a test and still far past 100:1 — the boundary
     * itself is tested separately against a lowered cap, which is what
     * {@see IngestCaps::with()} is for.
     */
    public static function buildRatioBomb(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('html/bomb.bin', str_repeat("\0", 8 * 1024 * 1024))
            ->toTarGz($stem.'.tar.gz');
    }

    /** 100,000 files, as Phase 03's exit criteria specify. */
    public static function buildFileCountBomb(string $stem): string
    {
        return ArchiveWriter::tarWithManyFiles($stem.'.tar', 100_000);
    }

    // ------------------------------------------------------------------- other

    public static function buildDuplicateEntry(string $stem): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('html/guide.html', "<p>first</p>\n")
            ->add('html/guide.html', "<p>second</p>\n")
            ->toTarGz($stem.'.tar.gz');
    }

    /** A JPEG. Must not publish as a tree of nothing. */
    public static function buildNotAnArchive(string $stem): string
    {
        $path = $stem.'.bin';
        file_put_contents($path, "\xFF\xD8\xFF\xE0".str_repeat('x', 4096));

        return $path;
    }

    /**
     * A header declaring 4,096 bytes for a member holding 32.
     *
     * 🛑 This is what makes the two-pass design necessary rather than tidy. The
     * caps are checked against declared sizes, so if declared and actual may
     * differ, the first pass checked nothing.
     */
    public static function buildLyingSizeHeader(string $stem): string
    {
        $path = (new ArchiveWriter)
            ->add('html/index.html', self::HTML)
            ->add('html/liar.html', str_repeat('x', 32))
            ->toTar($stem.'.tar');

        $bytes = (string) file_get_contents($path);
        $offset = strpos($bytes, 'html/liar.html');

        if ($offset === false) {
            throw new \RuntimeException('Could not find the member to corrupt.');
        }

        // The size field sits 124 bytes into the header, 12 bytes wide.
        $bytes = substr_replace($bytes, sprintf("%011o\0", 4096), $offset + 124, 12);

        // The checksum must still verify, or the reader refuses the header for
        // the wrong reason and the test proves nothing.
        $header = substr($bytes, $offset, 512);
        $blanked = substr_replace($header, str_repeat(' ', 8), 148, 8);
        $checksum = 0;

        for ($i = 0; $i < 512; $i++) {
            $checksum += ord($blanked[$i]);
        }

        $bytes = substr_replace($bytes, sprintf("%06o\0 ", $checksum), $offset + 148, 8);
        file_put_contents($path, $bytes);

        return $path;
    }
}
