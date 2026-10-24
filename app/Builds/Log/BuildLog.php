<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Log;

use App\Builds\BuildConfig;
use App\Credentials\SecretRedactor;

/**
 * One build's log: appended while it runs, read from any offset, capped.
 *
 * > §8.5.21: "The system MUST stream build logs line by line, strip NUL
 * > bytes, truncate lines over 8 KiB, cap the log at 10 MiB (head 2 MiB +
 * > tail 8 MiB with a marker), and 🛑 **redact every known secret value by
 * > literal, base64 and URL-encoded match before persistence or
 * > broadcast**, including values split across a chunk boundary."
 *
 * 🛑 **Redaction happens here, on the way in, and nowhere else.** "Before
 * persistence or broadcast" leaves exactly one safe place to do it: the
 * single function through which every line reaches a file. Redacting at
 * read time would leave the plaintext on disk; redacting in the runner
 * would mean shipping the secret list into the one process §11.2 keeps
 * credential-free. The runner does scrub the one credential it holds, so
 * the raw spool is not a hole — but this is the line that makes the
 * requirement true.
 *
 * 🛑 **"Split across a chunk boundary" is answered upstream, by reading
 * lines rather than chunks.** A secret cannot straddle two records here,
 * because a record is a whole line and the reader that produced it
 * buffered until the newline. That is why the runner's loop accumulates
 * into `$buffer` instead of scrubbing each `fread`, and why
 * `BuildLogRedactionTest` plants a secret that spans the 64 KiB read
 * boundary: the property is a consequence of the design, so it is worth a
 * test that would notice if the design changed.
 */
final class BuildLog
{
    /** §8.5.21: "truncate lines over 8 KiB". */
    public const MAX_LINE_BYTES = 8192;

    /** §8.5.21's head. Everything before this byte is kept for ever. */
    public const HEAD_BYTES = 2 * 1024 * 1024;

    /** §8.5.21's tail. The most recent this many bytes survive a cap. */
    public const TAIL_BYTES = 8 * 1024 * 1024;

    /**
     * Compaction happens at head+tail plus this, not at head+tail exactly.
     *
     * Without the slack every line past the cap would rewrite a 10 MiB
     * file. With it, the file oscillates between 10 and 11 MiB and the
     * rewrite happens once per megabyte of excess.
     */
    private const COMPACT_SLACK = 1024 * 1024;

    private int $seq = 0;

    private int $bytes = 0;

    private bool $capped = false;

    /** @var resource|null */
    private $handle = null;

    private function __construct(
        private readonly string $path,
        private readonly SecretRedactor $redactor,
    ) {}

    /**
     * The log for a build, by its hex id.
     *
     * Reopening an existing file resumes its sequence and byte count, so a
     * worker restarted mid-build continues the numbering rather than
     * starting again at 1 — which would give two different lines the same
     * address and break every client cursor.
     */
    public static function open(string $buildHex, ?SecretRedactor $redactor = null): self
    {
        $log = new self(self::pathFor($buildHex), $redactor ?? new SecretRedactor);
        $log->resume();

        return $log;
    }

    public static function pathFor(string $buildHex): string
    {
        if (preg_match('/^[0-9a-f]{32}$/', $buildHex) !== 1) {
            throw new \InvalidArgumentException('not a build id: '.substr($buildHex, 0, 64));
        }

        $directory = rtrim(
            BuildConfig::string('log_spool', storage_path('docup/build-logs')),
            '/',
        );

        if (! is_dir($directory)) {
            @mkdir($directory, 0o750, true);
        }

        return $directory.'/'.$buildHex.'.ndjson';
    }

    /**
     * Append one line.
     *
     * 🛑 The order is: strip NUL, truncate, **redact**, write. Redacting
     * after truncation is deliberate — a secret cut in half by the 8 KiB
     * rule would otherwise leave half of it in the file, and half a token
     * is still a disclosure of its length and prefix.
     *
     * Returns the line as it was stored, so a caller that also broadcasts
     * it is broadcasting the redacted form rather than its own copy.
     */
    public function append(string $text, string $stream = 'out'): LogLine
    {
        $text = str_replace("\0", '', rtrim($text, "\r\n"));

        if (strlen($text) > self::MAX_LINE_BYTES) {
            $text = substr($text, 0, self::MAX_LINE_BYTES).'… [line truncated at 8 KiB (§8.5.21)]';
        }

        $line = new LogLine(++$this->seq, (int) (microtime(true) * 1000), $stream, $this->redactor->scrub($text));

        $this->write($line);

        return $line;
    }

    /** @param list<LogLine> $lines */
    public function appendMany(array $lines): void
    {
        foreach ($lines as $line) {
            $this->append($line->text, $line->stream);
        }
    }

    /**
     * Read from a sequence number.
     *
     * 🛑 `$from` is **inclusive of the next line the client has not seen**:
     * a client that has rendered up to seq 40 asks for `from=41`. The
     * response carries `next`, so no client ever computes that itself —
     * which is what makes the contract survive the cap deleting lines.
     */
    public function read(int $from = 1, int $limit = 2000): LogPage
    {
        return self::pageFrom(self::rawLinesOf($this->path), $from, $limit);
    }

    /**
     * Assemble one page from any source of NDJSON records.
     *
     * 🛑 Shared with {@see BuildLogArchive} on purpose. A finished build's
     * log is read out of a gzip stream and a running build's out of a
     * plain file, and §8.5.22 says there is **one** offset-addressed
     * contract — so the paging, the cursor and the gap report are written
     * once and both storage shapes answer identically. Two copies would
     * differ at the edges, and the edges are where a cursor lives.
     *
     * @param  iterable<string>  $rawLines
     */
    public static function pageFrom(iterable $rawLines, int $from, int $limit): LogPage
    {
        $from = max(1, $from);
        $lines = [];
        $next = $from;
        $more = false;

        foreach ($rawLines as $raw) {
            $line = LogLine::decode($raw);

            if ($line === null || $line->seq < $from) {
                continue;
            }

            if (count($lines) >= $limit) {
                // More to come; the client's own `next` brings it back.
                $more = true;

                break;
            }

            $lines[] = $line;
            $next = $line->seq + 1;
        }

        /*
         * 🛑 The gap is measured against the first line ACTUALLY RETURNED,
         * not against the first line in the file. A client whose cursor
         * sits inside the hole the cap left would otherwise be handed the
         * tail with no indication that anything was missing — the sequence
         * numbers it receives are perfectly consistent, they simply start
         * somewhere it did not ask for.
         */
        $omitted = $lines === [] ? 0 : max(0, $lines[0]->seq - $from);

        return new LogPage($lines, $next, $more, $omitted === 0 ? null : $omitted);
    }

    /** @return \Generator<int, string> */
    private static function rawLinesOf(string $path): \Generator
    {
        $handle = @fopen($path, 'rb');

        if ($handle === false) {
            return;
        }

        try {
            while (($raw = fgets($handle)) !== false) {
                yield $raw;
            }
        } finally {
            fclose($handle);
        }
    }

    public function exists(): bool
    {
        return is_file($this->path);
    }

    public function lineCount(): int
    {
        return $this->seq;
    }

    public function byteCount(): int
    {
        return $this->bytes;
    }

    public function wasCapped(): bool
    {
        return $this->capped;
    }

    public function path(): string
    {
        return $this->path;
    }

    public function delete(): void
    {
        $this->closeHandle();
        @unlink($this->path);
    }

    private function write(LogLine $line): void
    {
        /*
         * One handle for the whole build rather than an open/close per
         * line. A chatty generator produces tens of thousands of lines and
         * the pipeline holds this object for the length of the build, so
         * the alternative is a hundred thousand syscalls for nothing.
         * `compact()` closes it, because a rename leaves the old handle
         * writing to an unlinked inode.
         */
        if (! is_resource($this->handle)) {
            $handle = @fopen($this->path, 'ab');

            if ($handle === false) {
                return;
            }

            $this->handle = $handle;
        }

        fwrite($this->handle, $line->encode());

        // The cap counts the TEXT, not the JSON framing: §8.5.21 is about
        // how much log there is, and an encoding change must not move the
        // ceiling.
        $this->bytes += strlen($line->text) + 1;

        if ($this->bytes > self::HEAD_BYTES + self::TAIL_BYTES + self::COMPACT_SLACK) {
            $this->compact();
        }
    }

    /**
     * §8.5.21's "head 2 MiB + tail 8 MiB with a marker", applied in place.
     *
     * 🛑 The middle is what goes, and that is the right half to lose. A
     * build's first lines say what it was asked to do and its last lines
     * say what went wrong; the forty thousand lines in between are a
     * generator enumerating files. Capping from the front would lose the
     * error, capping from the back would lose the configuration, and a
     * naive "stop at 10 MiB" — which is what Phase 06 shipped — loses the
     * error, every time, on exactly the builds that need reading.
     */
    private function compact(): void
    {
        $this->closeHandle();

        $handle = @fopen($this->path, 'rb');

        if ($handle === false) {
            return;
        }

        $head = [];
        $headBytes = 0;
        $tail = [];
        $tailBytes = 0;

        while (($raw = fgets($handle)) !== false) {
            $line = LogLine::decode($raw);

            if ($line === null) {
                continue;
            }

            $size = strlen($line->text) + 1;

            if ($headBytes + $size <= self::HEAD_BYTES) {
                $head[] = $line;
                $headBytes += $size;

                continue;
            }

            $tail[] = $line;
            $tailBytes += $size;

            // A ring, kept by dropping from the front. `array_shift` on a
            // list of a few thousand entries is cheap next to the file read
            // that already happened.
            while ($tailBytes > self::TAIL_BYTES && $tail !== []) {
                $dropped = array_shift($tail);
                $tailBytes -= strlen($dropped->text) + 1;
            }
        }

        fclose($handle);

        $omitted = ($head === [] || $tail === [])
            ? 0
            : max(0, ($tail[0]->seq - ($head[count($head) - 1]->seq + 1)));

        /*
         * 🛑 The marker takes the sequence number of the FIRST line it
         * replaced, which no surviving line carries. Reusing the head's
         * last number would give two different lines one address, and a
         * client that had already rendered that address would never see
         * the marker at all.
         */
        $marker = LogLine::system(
            $head === [] ? 1 : $head[count($head) - 1]->seq + 1,
            sprintf(
                '[%d lines omitted — this log exceeded 10 MiB, so the first 2 MiB and the last 8 MiB are kept (§8.5.21)]',
                $omitted,
            ),
        );

        $body = '';

        foreach ($head as $line) {
            $body .= $line->encode();
        }

        if ($omitted > 0) {
            $body .= $marker->encode();
        }

        foreach ($tail as $line) {
            $body .= $line->encode();
        }

        /*
         * Written beside and renamed, because a reader may be polling this
         * file right now and `rename` within a directory is atomic. A
         * truncate-and-rewrite would show a client an empty log for as long
         * as the write took.
         */
        $temporary = $this->path.'.compact';

        if (@file_put_contents($temporary, $body) === false) {
            return;
        }

        @rename($temporary, $this->path);

        $this->bytes = $headBytes + $tailBytes;
        $this->capped = true;
    }

    public function close(): void
    {
        $this->closeHandle();
    }

    private function closeHandle(): void
    {
        if (is_resource($this->handle)) {
            fclose($this->handle);
        }

        $this->handle = null;
    }

    /**
     * Pick up the sequence and byte count of an existing file.
     *
     * Reading the whole file to find the last sequence number is the honest
     * cost of not keeping a sidecar: it happens once per worker per build,
     * on a file bounded at 11 MiB, and a sidecar that disagreed with the
     * file would be worse than the read.
     */
    private function resume(): void
    {
        $handle = @fopen($this->path, 'rb');

        if ($handle === false) {
            return;
        }

        while (($raw = fgets($handle)) !== false) {
            $line = LogLine::decode($raw);

            if ($line === null) {
                continue;
            }

            $this->seq = max($this->seq, $line->seq);
            $this->bytes += strlen($line->text) + 1;
        }

        fclose($handle);
    }
}
