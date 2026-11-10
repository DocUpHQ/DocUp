<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Artifacts;

use App\Artifacts\ChromeInjector;
use App\Artifacts\InjectionOutcome;
use PHPUnit\Framework\TestCase;

/**
 * 🛑 §8.15.1's "exactly two tags" and §8.15.3's insertion point, at their edges.
 *
 * `Tests\Feature\Addons\AddonsCorpusTest` drives §9.4's corpus cases through
 * this class and `InjectionSafetyTest` drives whole artifacts through the
 * publish path. What is here is the part neither reaches: the **boundaries** of
 * three rules whose exact values are the rules.
 *
 * ## Why boundaries, specifically
 *
 * §9.4 makes a ≥75% mutation score on changed domain code a requirement for a
 * security-critical phase, and this class is Phase 28's target — §8.15.3's
 * search is the control the whole phase turns on, and a surviving mutation in
 * it is a **corrupted document with a passing coverage record**, which is
 * exactly the defect the corpus found by hand.
 *
 * 🛑 Measuring it found three real gaps rather than confirming coverage:
 *
 * 1. Nothing asserted the **order** of the two tags, or that there are exactly
 *    two. Every `ConcatSwitchSides` and `ConcatRemoveRight` mutation on
 *    `tags()` survived — the tags could have been emitted backwards, or the
 *    meta dropped entirely, with every other test still green.
 * 2. Nothing asserted the navigational-stub exemption's **bounds**. §8.15.3
 *    carves stubs out of the warning and the carve-out turns on two numbers;
 *    both could be moved freely.
 * 3. Nothing asserted which characters may follow `<script` or `</head`, so
 *    `<scripture-notes>` and `</headache>` were covered by one corpus case
 *    each and not by the rule.
 *
 * All three are behavioural rules with no test, which is what a mutation score
 * is for. They are tested here because they are worth testing, and the score
 * is the symptom that found them.
 */
final class ChromeInjectorTest extends TestCase
{
    private const string BUILD = '0192f0a0-0000-7000-8000-000000000001';

    private function injector(int $maxBytes = 4_194_304): ChromeInjector
    {
        return new ChromeInjector($maxBytes);
    }

    private function inject(string $html, ?string $buildId = null): string
    {
        return $this->injector()->inject($html, $buildId ?? self::BUILD)->bytes;
    }

    private function outcome(string $html, int $maxBytes = 4_194_304): InjectionOutcome
    {
        return $this->injector($maxBytes)->inject($html, self::BUILD)->outcome;
    }

    // ---------------------------------------------------- §8.15.1's two tags

    /**
     * 🛑 §8.15.1: "**exactly two** […] tags before the first `</head>`: a
     * deferred script at a stable, non-content-hashed path, and
     * `<meta name="docup" content="b=<build_uuid>">`".
     *
     * Asserted as the exact string, in order, because every part of it is a
     * requirement: `defer` (the script must not block the document it was
     * inserted into), the stable path, the meta's name, and `b=` followed by
     * the build identifier **and nothing else**.
     */
    public function test_exactly_two_tags_in_the_order_the_requirement_states(): void
    {
        $injected = $this->inject('<!doctype html><html><head></head><body>p</body></html>');

        $this->assertSame(
            '<!doctype html><html><head>'
            .'<script defer src="/_/addons/docup.js"></script>'
            .'<meta name="docup" content="b='.self::BUILD.'">'
            .'</head><body>p</body></html>',
            $injected,
        );

        // Two, not one and not three.
        $this->assertSame(1, substr_count($injected, '<script'));
        $this->assertSame(1, substr_count($injected, '<meta name="docup"'));

        /*
         * 🛑 The script BEFORE the meta. The order is in the requirement's own
         * sentence, and a `defer`red script that ran before the meta existed in
         * the DOM would find no build id — the runtime reads the meta first and
         * does nothing without it.
         */
        $this->assertLessThan(
            strpos($injected, '<meta name="docup"'),
            strpos($injected, '<script defer'),
        );
    }

    /** §8.15.1: the loader path is the published constant, never a copy. */
    public function test_the_loader_path_is_the_constant(): void
    {
        $this->assertStringContainsString(
            'src="'.ChromeInjector::LOADER_PATH.'"',
            $this->inject('<html><head></head><body>p</body></html>'),
        );
    }

    /**
     * 🛑 The build id is escaped, and the escaping is asserted on both the
     * presence of the entity and the absence of the raw markup.
     *
     * A test that only checked for `&quot;` would pass for an implementation
     * that escaped the value and also emitted it raw somewhere else.
     */
    public function test_the_build_identifier_is_escaped(): void
    {
        $injected = $this->inject('<html><head></head><body>p</body></html>', '"><script>alert(1)</script>');

        $this->assertStringNotContainsString('<script>alert(1)</script>', $injected);
        $this->assertStringContainsString('content="b=&quot;&gt;&lt;script&gt;', $injected);

        // And the document still has exactly one real script: ours.
        $this->assertSame(1, substr_count($injected, '<script defer'));
    }

    // ------------------------------------------- §8.15.3's insertion point

    /**
     * 🛑 §8.15.3's tolerance, at the edges: every character that may sit
     * between `head` and `>` and nothing else.
     *
     * The requirement names `</HEAD>` and `</head >` as "both legal and both
     * [occurring]", and says a naive fixed-string search "produces false
     * failures on valid documents". So the false failures are what is tested.
     */
    public function test_every_tolerated_spelling_of_the_head_close(): void
    {
        foreach ([
            '</head>',
            '</HEAD>',
            '</Head>',
            '</head >',
            "</head\t>",
            "</head\n>",
            "</head\r>",
            "</head\f>",
            "</head \t\n\r\f >",
        ] as $close) {
            $this->assertSame(
                InjectionOutcome::Injected,
                $this->outcome('<html><head><title>x</title>'.$close.'<body>p</body></html>'),
                $close.' is a legal head close and must be found',
            );
        }
    }

    /** 🛑 And what is NOT a head close, which the same tolerance must refuse. */
    public function test_what_is_not_a_head_close(): void
    {
        foreach ([
            // A longer tag name. `</headache>` is not `</head>`.
            '<html><head><p>prose enough to not be a stub, with several words in it</p></headache></html>',
            // Whitespace INSIDE the name.
            '<html><head><p>prose enough to not be a stub, with several words in it</p></hea d></html>',
            // Truncated at the end of the document.
            '<html><head><p>prose enough to not be a stub, with several words in it</p></head',
            // An attribute, which an end tag may not carry.
            '<html><head><p>prose enough to not be a stub, with several words in it</p></head id="x"></html>',
        ] as $document) {
            $this->assertSame(
                InjectionOutcome::RefusedNoHead,
                $this->outcome($document),
                'must not be read as a head close: '.$document,
            );
        }
    }

    /**
     * 🛑 Which characters may follow `<script` and `<style`, at the edges.
     *
     * The rule exists because a fixed-string search for `<script` would read
     * `<scripture-notes>` as a script element and skip the rest of the
     * document — so a documentation site about scripture would lose its
     * chrome, and nothing would say why.
     */
    public function test_what_opens_a_raw_text_element_and_what_does_not(): void
    {
        // These ARE raw-text elements: the decoy inside them is skipped, so the
        // tags land at the REAL head close that follows.
        foreach ([
            '<script>"</head>"</script>',
            '<script >"</head>"</script>',
            "<script\n>\"</head>\"</script>",
            '<script src="a.js">"</head>"</script>',
            '<SCRIPT>"</head>"</SCRIPT>',
            '<style>/* </head> */</style>',
            '<style type="text/css">/* </head> */</style>',
        ] as $raw) {
            $document = '<html><head>'.$raw.'</head><body>p</body></html>';
            $injected = $this->inject($document);

            $this->assertGreaterThan(
                stripos($injected, '</head>'),
                strpos($injected, ChromeInjector::LOADER_PATH),
                'the decoy inside '.$raw.' must be skipped',
            );
        }

        /*
         * And these are NOT: the element name merely begins with the same
         * letters, so the scan must carry on and find the head close
         * immediately after it rather than skipping to a `</script>` that
         * never comes.
         */
        foreach ([
            '<scripture-notes></scripture-notes>',
            '<scriptable id="x"></scriptable>',
            '<styled-text></styled-text>',
            '<stylesheet-link></stylesheet-link>',
        ] as $lookalike) {
            $this->assertSame(
                InjectionOutcome::Injected,
                $this->outcome('<html><head>'.$lookalike.'</head><body>p</body></html>'),
                $lookalike.' is not a raw-text element',
            );
        }
    }

    /** An unterminated raw-text element or comment refuses rather than guesses. */
    public function test_an_unterminated_region_refuses(): void
    {
        foreach ([
            '<html><head><script>var a = 1;</head><body>prose enough to not be a stub here</body></html>',
            '<html><head><!-- </head><body>prose enough to not be a stub here</body></html>',
            '<html><head><style>a{} </head><body>prose enough to not be a stub here</body></html>',
            '<html><head><![CDATA[ </head> <body>prose enough to not be a stub</body></html>',
        ] as $document) {
            $this->assertSame(
                InjectionOutcome::RefusedNoHead,
                $this->outcome($document),
                'an unterminated region must refuse: '.$document,
            );
        }
    }

    // --------------------------------- §8.15.3's navigational-stub exemption

    /**
     * 🛑 The stub exemption's size bound, at both sides of it.
     *
     * §8.15.3 excludes "a document with no `<head>` element whose body is only
     * a meta-refresh or a `location=` assignment" from the **warning**. The
     * carve-out turns on two numbers, and both have to be exact: too generous
     * and a real page stops warning, too tight and every Antora site warns
     * forever (ADR 0002).
     *
     * The size bound is 4 KiB. A redirect page padded past it with **comment**
     * bytes is still only a redirect to a reader, and is deliberately no longer
     * excused: at that size it is not the stub the exemption was carved for.
     */
    public function test_the_stub_size_bound_is_exact(): void
    {
        $redirect = '<html><body><script>location.replace("en/latest/")</script>';
        $tail = '</body></html>';

        // Just inside 4096 bytes: still a stub.
        $padding = 4_096 - strlen($redirect) - strlen($tail) - strlen('<!---->');

        $this->assertSame(
            InjectionOutcome::SkippedStub,
            $this->outcome($redirect.'<!--'.str_repeat('x', $padding).'-->'.$tail),
        );

        // One byte over: no longer excused.
        $this->assertSame(
            InjectionOutcome::RefusedNoHead,
            $this->outcome($redirect.'<!--'.str_repeat('x', $padding + 1).'-->'.$tail),
        );
    }

    /**
     * 🛑 And the text bound, which is what stops the exemption swallowing a
     * real page.
     *
     * 64 characters of visible text after tags are stripped. A document that
     * redirects **and says something** is a document.
     */
    public function test_the_stub_text_bound_is_exact(): void
    {
        $document = static fn (string $prose): string => '<html><body>'
            .'<script>location="en/latest/"</script>'.$prose.'</body></html>';

        $this->assertSame(InjectionOutcome::SkippedStub, $this->outcome($document('')));

        /*
         * Padded to EXACTLY the bound, measured with the same expression the
         * injector uses rather than computed from the parts: a stripped tag
         * leaves a space behind, so arithmetic over the pieces is off by one
         * and silently picks the wrong side of the boundary. Found that way.
         */
        $prose = '';

        while (self::visibleLength($document($prose)) < 64) {
            $prose .= 'a';
        }

        $this->assertSame(64, self::visibleLength($document($prose)));
        $this->assertSame(
            InjectionOutcome::SkippedStub,
            $this->outcome($document($prose)),
            'exactly at the bound is still a stub',
        );

        // One character of prose more: a document, and it warns.
        $this->assertSame(65, self::visibleLength($document($prose.'b')));
        $this->assertSame(
            InjectionOutcome::RefusedNoHead,
            $this->outcome($document($prose.'b')),
            'one character over the bound is a document',
        );
    }

    /**
     * The visible text length the stub heuristic measures.
     *
     * 🛑 The same two expressions the injector applies, in the same order,
     * because the boundary assertions above are only meaningful if both sides
     * count the same characters.
     */
    private static function visibleLength(string $html): int
    {
        $text = trim((string) preg_replace('/<[^>]*>/', ' ', $html));

        return strlen(trim((string) preg_replace('/\s+/', ' ', $text)));
    }

    /** 🛑 A document with no head and no redirect at all is never a stub. */
    public function test_a_document_without_a_redirect_is_never_a_stub(): void
    {
        $this->assertSame(
            InjectionOutcome::RefusedNoHead,
            $this->outcome('<html><body><h1>x</h1></body></html>'),
            'a short headless document still warns: the exemption is for redirects',
        );
    }

    /** Both of §8.15.3's redirect spellings are recognised. */
    public function test_both_redirect_mechanisms_are_recognised(): void
    {
        foreach ([
            '<meta http-equiv="refresh" content="0; url=en/latest/">',
            '<meta http-equiv=refresh content="0;url=en/latest/">',
            "<meta http-equiv = 'refresh' content='0'>",
            '<script>location="en/latest/"</script>',
            '<script>location = "en/latest/"</script>',
            '<script>location.replace("en/latest/")</script>',
            '<script>location.assign("en/latest/")</script>',
            '<script>location.href="en/latest/"</script>',
        ] as $redirect) {
            $this->assertSame(
                InjectionOutcome::SkippedStub,
                $this->outcome('<html><body>'.$redirect.'</body></html>'),
                $redirect.' is a navigational stub',
            );
        }
    }

    // ------------------------------------------------ §8.15.4's refusals

    /** 🛑 The byte ceiling is checked first, and is exact. */
    public function test_the_byte_ceiling_is_exact_and_checked_before_anything_else(): void
    {
        $prefix = '<html><head></head><body>';
        $suffix = '</body></html>';
        $ceiling = 512;
        $body = str_repeat('x', $ceiling - strlen($prefix) - strlen($suffix));

        $this->assertSame(
            InjectionOutcome::Injected,
            $this->outcome($prefix.$body.$suffix, $ceiling),
            'exactly at the ceiling is permitted',
        );

        $this->assertSame(
            InjectionOutcome::RefusedTooLarge,
            $this->outcome($prefix.$body.'y'.$suffix, $ceiling),
            'one byte over is refused',
        );

        /*
         * 🛑 Checked BEFORE the UTF-8 validation and before the scan, which is
         * the ordering that matters: everything below it holds the whole
         * document in memory. An oversized non-UTF-8 document reports the size,
         * not the encoding.
         */
        $this->assertSame(
            InjectionOutcome::RefusedTooLarge,
            $this->outcome('<html><head></head><body>'.str_repeat("\x93\xfa", 400).'</body></html>', 64),
        );
    }

    /** §8.15.4: non-UTF-8 is refused, and the bytes are returned untouched. */
    public function test_non_utf8_is_refused_with_its_bytes_intact(): void
    {
        $document = "<html><head></head><body>\x93\xfa\x96\x7b</body></html>";
        $result = $this->injector()->inject($document, self::BUILD);

        $this->assertSame(InjectionOutcome::RefusedNonUtf8, $result->outcome);
        $this->assertSame($document, $result->bytes);
    }

    /** `handles()` names HTML and nothing else (§8.15.1's "built HTML"). */
    public function test_handles_only_html_extensions(): void
    {
        foreach (['a.html', 'a.htm', 'a.xhtml', 'A.HTML', 'deep/path/a.Html'] as $path) {
            $this->assertTrue(ChromeInjector::handles($path), $path);
        }

        foreach (['a.css', 'a.js', 'a.json', 'a.png', 'a.html.gz', 'a', 'a.htmlx', 'html'] as $path) {
            $this->assertFalse(ChromeInjector::handles($path), $path);
        }
    }

    /**
     * 🛑 An artifact stamped with this version carries this behaviour.
     *
     * The constant is the whole mechanism behind §8.15.4's re-ingest job, so a
     * change to the insertion point that forgot to bump it would leave every
     * affected artifact unfindable. Asserted so the bump is a decision somebody
     * makes rather than one somebody forgets.
     */
    public function test_the_injector_version_is_stamped_at_two(): void
    {
        $this->assertSame(
            2,
            ChromeInjector::VERSION,
            'version 1 inserted into comments and script strings; see headCloseAt()',
        );
    }
}
