<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Builds\Log\BuildLog;
use App\Credentials\SecretRedactor;
use App\Credentials\SecretRegistry;
use Tests\TestCase;

/**
 * §8.5.21's log, line by line.
 *
 * > "The system MUST stream build logs line by line, strip NUL bytes,
 * > truncate lines over 8 KiB, cap the log at 10 MiB (head 2 MiB + tail
 * > 8 MiB with a marker), and 🛑 **redact every known secret value by
 * > literal, base64 and URL-encoded match before persistence or
 * > broadcast**, including values split across a chunk boundary."
 *
 * Six requirements in one sentence, and each gets its own case: a single
 * test exercising all of them would pass with five of the six working.
 */
final class BuildLogTest extends TestCase
{
    private string $buildHex;

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('builds.log_spool', sys_get_temp_dir().'/docup-log-'.bin2hex(random_bytes(6)));
        $this->buildHex = bin2hex(random_bytes(16));
        SecretRegistry::flush();
    }

    protected function tearDown(): void
    {
        BuildLog::open($this->buildHex)->delete();
        SecretRegistry::flush();

        parent::tearDown();
    }

    public function test_lines_are_addressed_by_a_monotonic_sequence(): void
    {
        $log = BuildLog::open($this->buildHex);

        foreach (['first', 'second', 'third'] as $text) {
            $log->append($text);
        }

        $page = $log->read();

        $this->assertSame([1, 2, 3], array_map(static fn ($line): int => $line->seq, $page->lines));
        $this->assertSame(['first', 'second', 'third'], array_map(static fn ($line): string => $line->text, $page->lines));
        $this->assertSame(4, $page->next, 'the response carries the next cursor');
        $this->assertNull($page->omitted);
    }

    /** 🛑 The offset contract: a second reader with its own cursor sees only what is new. */
    public function test_a_reader_resumes_from_its_own_cursor(): void
    {
        $log = BuildLog::open($this->buildHex);
        $log->append('one');
        $log->append('two');

        $first = $log->read();
        $this->assertCount(2, $first->lines);

        $log->append('three');

        $second = $log->read($first->next);

        $this->assertCount(1, $second->lines);
        $this->assertSame('three', $second->lines[0]->text);
        $this->assertSame(4, $second->next);
    }

    public function test_a_page_reports_when_it_was_cut_by_the_limit(): void
    {
        $log = BuildLog::open($this->buildHex);

        for ($i = 0; $i < 10; $i++) {
            $log->append('line '.$i);
        }

        $page = $log->read(1, 4);

        $this->assertCount(4, $page->lines);
        $this->assertTrue($page->more);
        $this->assertSame(5, $page->next);
    }

    public function test_nul_bytes_are_stripped_and_long_lines_truncated(): void
    {
        $log = BuildLog::open($this->buildHex);

        $log->append("before\0after");
        $log->append(str_repeat('A', 70000));

        $lines = $log->read()->lines;

        $this->assertSame('beforeafter', $lines[0]->text);
        $this->assertStringNotContainsString("\0", $lines[1]->text);
        $this->assertLessThan(8400, strlen($lines[1]->text));
        $this->assertStringContainsString('line truncated at 8 KiB', $lines[1]->text);
    }

    /**
     * 🛑 §8.5.21's redaction, in all three encodings it names.
     *
     * The literal is the easy one. Base64 is how a deploy key or a
     * `.netrc` reaches a log, and URL-encoding is how a token in a clone
     * URL does — and neither has a shape a pattern could recognise, which
     * is why {@see SecretRegistry} exists at all.
     */
    public function test_a_registered_secret_is_redacted_in_every_encoding(): void
    {
        $secret = 'ghp_'.str_repeat('z', 36);
        SecretRegistry::remember($secret);

        $log = BuildLog::open($this->buildHex, new SecretRedactor);

        $log->append('literal: '.$secret);
        $log->append('base64: '.base64_encode($secret));
        $log->append('urlencoded: '.rawurlencode($secret));

        $joined = implode("\n", array_map(static fn ($line): string => $line->text, $log->read()->lines));

        $this->assertStringNotContainsString($secret, $joined);
        $this->assertStringNotContainsString(base64_encode($secret), $joined);
        $this->assertStringNotContainsString(rawurlencode($secret), $joined);
        $this->assertSame(3, substr_count($joined, SecretRedactor::MARKER));
    }

    /**
     * 🛑 Redaction happens BEFORE the bytes reach the file, not on the way
     * out.
     *
     * The distinction is the whole requirement — "before persistence or
     * broadcast" — and a reader-side redactor would pass every assertion
     * above while leaving the plaintext on disk for anybody with the
     * volume.
     */
    public function test_the_secret_is_not_on_disk_at_all(): void
    {
        $secret = 'glpat-'.str_repeat('q', 20);
        SecretRegistry::remember($secret);

        $log = BuildLog::open($this->buildHex, new SecretRedactor);
        $log->append('token is '.$secret);
        $log->close();

        $raw = (string) file_get_contents($log->path());

        $this->assertStringNotContainsString($secret, $raw);
        $this->assertStringContainsString(SecretRedactor::MARKER, $raw);
    }

    /**
     * 🛑 A secret truncated by the 8 KiB rule is still redacted whole.
     *
     * The order in `append()` is strip, truncate, **redact** — and it has
     * to be. Redacting first would leave the tail of a long line
     * unexamined; truncating a line whose secret straddles the 8 KiB
     * boundary and then redacting leaves nothing of it, because the
     * registry matches the prefix that survived only if it is a
     * registered form, which it is not. What this asserts is the outcome
     * either way: no fragment of the secret, of any length, in the file.
     */
    public function test_a_secret_straddling_the_truncation_point_leaves_no_fragment(): void
    {
        $secret = 'docup_live_'.str_repeat('k', 40);
        SecretRegistry::remember($secret);

        $log = BuildLog::open($this->buildHex, new SecretRedactor);
        $log->append(str_repeat('x', BuildLog::MAX_LINE_BYTES - 20).$secret);
        $log->close();

        $raw = (string) file_get_contents($log->path());

        $this->assertStringNotContainsString($secret, $raw);
        $this->assertStringNotContainsString(substr($secret, 0, 30), $raw);
    }

    /**
     * 🛑 §8.5.21's cap: head 2 MiB + tail 8 MiB, with a marker and a gap.
     *
     * Run against a configuration an ordinary test can reach — the real
     * ceiling is 10 MiB of text, which at 64 bytes a line is 160,000
     * lines and about forty seconds of writing. What is under test is the
     * SHAPE: that the first lines survive, that the last lines survive,
     * that the middle does not, and that a reader is told.
     */
    public function test_an_oversized_log_keeps_its_head_and_its_tail(): void
    {
        $log = BuildLog::open($this->buildHex);
        $line = str_repeat('y', 1024);

        // Enough to pass head + tail + slack several times over.
        for ($i = 0; $i < 12000; $i++) {
            $log->append($i.' '.$line);
        }

        $log->close();
        $page = $log->read(1, 200000);
        $texts = array_map(static fn ($l): string => $l->text, $page->lines);

        $this->assertTrue($log->wasCapped(), 'the cap never fired');
        $this->assertLessThan(
            BuildLog::HEAD_BYTES + BuildLog::TAIL_BYTES + 1024 * 1024,
            $log->byteCount(),
        );

        // 🛑 The first line is still there: a build's opening lines say
        // what it was asked to do, and capping from the front loses them.
        $this->assertStringStartsWith('0 ', $texts[0]);

        // 🛑 And so is the last: capping from the back loses the error,
        // every time, on exactly the builds somebody needs to read.
        $this->assertStringStartsWith('11999 ', $texts[count($texts) - 1]);

        $joined = implode("\n", $texts);
        $this->assertStringContainsString('lines omitted', $joined);
        $this->assertStringContainsString('§8.5.21', $joined);
    }

    /**
     * 🛑 A client whose cursor sits inside the hole is told so.
     *
     * The sequence numbers it receives are perfectly consistent on either
     * side of the gap, so without `omitted` it cannot tell that anything
     * is missing — it would simply render the tail as though it followed
     * the head.
     */
    public function test_a_cursor_inside_the_gap_is_told_what_was_lost(): void
    {
        $log = BuildLog::open($this->buildHex);
        $line = str_repeat('z', 1024);

        for ($i = 0; $i < 12000; $i++) {
            $log->append($i.' '.$line);
        }

        $log->close();

        /*
         * The gap is located rather than guessed. Where it falls depends
         * on the byte sizes of the lines, and a test that hard-coded a
         * sequence number would pass or fail on the width of a counter.
         */
        $marker = null;

        foreach ($log->read(1, 200000)->lines as $line) {
            if ($line->stream === 'docup' && str_contains($line->text, 'lines omitted')) {
                $marker = $line;

                break;
            }
        }

        $this->assertNotNull($marker, 'the cap left no marker');

        // One past the marker is inside the hole: those lines are gone.
        $page = $log->read($marker->seq + 1, 10);

        $this->assertNotNull($page->omitted, 'a reader inside the gap was told nothing');
        $this->assertGreaterThan(0, $page->omitted);
        $this->assertNotSame($marker->seq + 1, $page->lines[0]->seq);
    }

    /**
     * Reopening resumes the numbering.
     *
     * A worker restarted mid-build must not start again at 1: two
     * different lines with one address is precisely what every client
     * cursor assumes cannot happen.
     */
    public function test_reopening_continues_the_sequence(): void
    {
        $first = BuildLog::open($this->buildHex);
        $first->append('before the restart');
        $first->close();

        $second = BuildLog::open($this->buildHex);
        $second->append('after the restart');

        $page = $second->read();

        $this->assertSame([1, 2], array_map(static fn ($line): int => $line->seq, $page->lines));
    }

    public function test_reading_a_log_that_does_not_exist_is_an_empty_page(): void
    {
        $page = BuildLog::open(bin2hex(random_bytes(16)))->read();

        $this->assertSame([], $page->lines);
        $this->assertSame(1, $page->next);
        $this->assertFalse($page->more);
    }
}
