<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Serving;

use App\Serving\CanonicalPath;
use App\Serving\RejectionReason;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * §8.9.6 — byte-canonical path rejection.
 *
 * 🛑 The hostile cases come from `corpus.json`, which Phase 00 wrote before any
 * resolver existed. Its `path` and `cache_deception` categories are the two that
 * land here, and both commit to **400** — not 404, and not "normalise and
 * serve".
 *
 * No database and no HTTP: {@see CanonicalPath} has no dependencies, which is
 * what lets the middleware call it before anything else on the request. A test
 * that needed a booted application to exercise it would be evidence that it had
 * acquired one.
 */
final class CanonicalPathTest extends TestCase
{
    /**
     * Every `path` and `cache_deception` case the corpus states as a path.
     *
     * `cache_deception-004` is excluded by its own shape: its input is a prose
     * instruction ("GET a known-private asset with no credentials through the
     * real edge") and its expectation is `404-or-403-never-200`. That is
     * §8.12.22's containment self-test against a running edge, not a string this
     * class can judge.
     *
     * @return \Generator<string, array{0: string, 1: string}>
     */
    public static function hostilePaths(): \Generator
    {
        /** @var array{cases: list<array<string, string>>} $corpus */
        $corpus = json_decode(
            (string) file_get_contents(__DIR__.'/../../Fixtures/AbuseCorpus/corpus.json'),
            true,
            64,
            JSON_THROW_ON_ERROR,
        );

        foreach ($corpus['cases'] as $case) {
            if (! in_array($case['category'] ?? null, ['path', 'cache_deception'], true)) {
                continue;
            }

            if (! str_starts_with($case['input'] ?? '', '/')) {
                continue;
            }

            yield $case['id'].' '.$case['input'] => [$case['input'], $case['expect']];
        }
    }

    #[DataProvider('hostilePaths')]
    public function test_a_hostile_path_is_refused_with_the_status_the_corpus_commits_to(
        string $path,
        string $expect,
    ): void {
        $reason = CanonicalPath::reject($path);

        $this->assertInstanceOf(
            RejectionReason::class,
            $reason,
            "The corpus expects {$expect} for [{$path}]; it was accepted as canonical.",
        );

        $this->assertSame((int) $expect, $reason->status(), "for [{$path}], reason {$reason->value}");

        /*
         * 🛑 And it must be a rejection that fires BEFORE resolution. §8.9.6:
         * "its position in the pipeline is the whole of its value". A 400 that
         * arrived after a cache lookup would satisfy the status assertion above
         * and none of the requirement.
         */
        $this->assertTrue(
            $reason->precedesResolution(),
            "[{$path}] was refused as {$reason->value}, which is not a pre-resolution rejection",
        );
    }

    /**
     * @return \Generator<string, array{0: string, 1: RejectionReason}>
     */
    public static function nonCanonicalPaths(): \Generator
    {
        yield 'relative' => ['en/latest/', RejectionReason::PathNotAbsolute];
        yield 'empty segment mid-path' => ['/en//latest/', RejectionReason::PathEmptySegment];
        yield 'protocol-relative' => ['//evil.example.com/', RejectionReason::PathEmptySegment];
        yield 'dot segment' => ['/en/./latest/', RejectionReason::PathDotSegment];
        yield 'dot-dot segment' => ['/en/../latest/', RejectionReason::PathDotSegment];
        // Both encoded spellings are refused as over-encoded rather than as dot
        // segments, because `.` never needs escaping and the canonicality rule
        // reaches it first. Asserted as what actually fires: a test that named
        // the reason it felt ought to fire would be asserting an intention.
        yield 'encoded dot-dot, uppercase' => ['/en/%2E%2E/latest/', RejectionReason::PathNonCanonicalEscape];
        yield 'encoded dot-dot, lowercase' => ['/en/%2e%2e/latest/', RejectionReason::PathNonCanonicalEscape];
        yield 'encoded separator' => ['/en%2Flatest/', RejectionReason::PathIllegalByte];
        yield 'literal percent' => ['/en/latest/100%25.html', RejectionReason::PathIllegalByte];
        yield 'backslash' => ['/en\\latest\\', RejectionReason::PathBackslash];
        yield 'raw NUL' => ["/en/latest/guide\0.html", RejectionReason::PathControlByte];
        yield 'encoded NUL' => ['/en/latest/guide%00.html', RejectionReason::PathControlByte];
        yield 'encoded DEL' => ['/en/latest/guide%7F.html', RejectionReason::PathControlByte];
        yield 'over-encoded letter' => ['/en/l%61test/', RejectionReason::PathNonCanonicalEscape];
        yield 'malformed escape' => ['/en/latest/g%ZZ.html', RejectionReason::PathNonCanonicalEscape];
        yield 'truncated escape' => ['/en/latest/g%2', RejectionReason::PathNonCanonicalEscape];
        yield 'semicolon' => ['/en/latest/a;b.css', RejectionReason::PathIllegalByte];
        yield 'raw non-ascii' => ["/en/latest/caf\xC3\xA9.html", RejectionReason::PathIllegalByte];
        yield 'lone continuation byte' => ['/en/latest/%80.html', RejectionReason::PathNotUtf8];
        yield 'suffix confusion, html' => ['/en/latest/p.html/x.css', RejectionReason::PathSuffixConfusion];
        yield 'suffix confusion, uppercase' => ['/en/latest/P.HTML/x.css', RejectionReason::PathSuffixConfusion];
        yield 'suffix confusion, pdf' => ['/en/latest/m.pdf/x.js', RejectionReason::PathSuffixConfusion];
        yield 'too long' => ['/'.str_repeat('a', 2048), RejectionReason::PathTooLong];
    }

    #[DataProvider('nonCanonicalPaths')]
    public function test_it_names_the_specific_reason(string $path, RejectionReason $expected): void
    {
        /*
         * The exact reason matters, not just the refusal. §8.9.6's rejections
         * reach `X-DocUp-Resolver` and an operator's alerting, and "400" cannot
         * distinguish a traversal attempt from a trailing-slash mistake — so a
         * test that only asserted "refused" would let the reasons drift into
         * each other unnoticed.
         */
        $this->assertSame($expected, CanonicalPath::reject($path), "for [{$path}]");
    }

    /**
     * @return \Generator<string, array{0: string}>
     */
    public static function canonicalPaths(): \Generator
    {
        yield 'root' => ['/'];
        yield 'version root' => ['/en/latest/'];
        yield 'a document' => ['/en/latest/guide.html'];
        yield 'a nested asset' => ['/en/latest/_static/css/site.css'];
        yield 'percent-encoded utf-8' => ['/en/latest/caf%C3%A9.html'];
        yield 'reserved namespace' => ['/_/addons'];
        yield 'well-known' => ['/.well-known/acme-challenge/token'];
        yield 'tilde and friends' => ['/en/latest/a~b!c$d&e.html'];
        yield 'a dotfile that is not a dot segment' => ['/en/latest/.nojekyll'];
        yield 'a directory named like a stylesheet' => ['/en/latest/theme.css/x.map'];
        yield 'a document as the final segment' => ['/en/latest/deep/nested/index.html'];
        yield 'at the byte ceiling' => ['/'.str_repeat('a', 2047)];
    }

    #[DataProvider('canonicalPaths')]
    public function test_it_accepts_a_canonical_path(string $path): void
    {
        $reason = CanonicalPath::reject($path);

        // An explicit fail rather than assertNull with an interpolated message:
        // the message would have to read the reason it is asserting is absent,
        // and a false positive here needs to name which rule over-reached.
        if ($reason !== null) {
            $this->fail("[{$path}] is canonical but was refused as {$reason->value}");
        }

        $this->assertTrue(CanonicalPath::isCanonical($path));
    }

    /**
     * 🛑 The property that makes byte-identity worth the strictness: a document
     * has exactly one URL.
     *
     * Every spelling below names the same file, and all but one are refused.
     * That is the cache-key surface collapsing to one entry per document, which
     * is what makes a strong ETag and a shared cache safe at all.
     */
    public function test_one_document_has_exactly_one_accepted_spelling(): void
    {
        $spellings = [
            '/en/latest/guide.html',        // the canonical one
            '/en/latest/./guide.html',
            '/en/latest//guide.html',
            '/en/latest/%67uide.html',
            '/en/latest/g%75ide.html',
            '/en/latest/sub/../guide.html',
            '/en/latest/guide.html;x',
            '/en/latest/guide.html%00',
        ];

        $accepted = array_values(array_filter(
            $spellings,
            static fn (string $path): bool => CanonicalPath::isCanonical($path),
        ));

        $this->assertSame(['/en/latest/guide.html'], $accepted);
    }
}
