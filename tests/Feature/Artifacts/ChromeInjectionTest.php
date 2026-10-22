<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Artifacts;

use App\Artifacts\ArtifactIngestor;
use App\Artifacts\ChromeInjector;
use App\Artifacts\Exceptions\IngestRejected;
use App\Artifacts\IngestCaps;
use App\Artifacts\InjectionCoverage;
use App\Artifacts\InjectionOutcome;
use App\Artifacts\LocalArtifactStore;
use App\Support\Uuid;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\ArchiveWriter;
use Tests\TestCase;

/**
 * §8.15 — ingest-time chrome injection.
 *
 * 🛑 The two requirements that are easy to get subtly wrong, and which this file
 * exists to hold:
 *
 * - §8.15.3's **stub exclusion**. A navigational stub is recorded and must not
 *   warn, "or every Antora site warns on every build forever and operators learn
 *   to ignore injection warnings (ADR 0002)". A warning somebody has learned to
 *   ignore is worse than no warning.
 * - §8.15.4's **non-UTF-8 refusal**. Inserting ASCII bytes would appear to work;
 *   it is refused because "a mis-declared charset is an XSS vector" and the
 *   declaration cannot be checked without the parsing §8.15.3 forbids.
 */
final class ChromeInjectionTest extends TestCase
{
    private string $fixtures;

    private ArtifactIngestor $ingestor;

    private ChromeInjector $injector;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');

        $this->fixtures = sys_get_temp_dir().'/docup-chrome-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->injector = ChromeInjector::fromConfig();
        $this->ingestor = new ArtifactIngestor(
            new LocalArtifactStore('artifacts'),
            IngestCaps::fromConfig(),
            $this->injector,
        );
    }

    protected function tearDown(): void
    {
        if (is_dir($this->fixtures)) {
            foreach ((array) glob($this->fixtures.'/*') as $file) {
                if (is_string($file)) {
                    @unlink($file);
                }
            }

            @rmdir($this->fixtures);
        }

        parent::tearDown();
    }

    // -------------------------------------------------------- the two tags

    /** 🛑 §8.15.1: "exactly two project- and version-agnostic tags". */
    public function test_it_inserts_exactly_two_tags_before_the_first_head_close(): void
    {
        $build = '019318f0-0000-7000-8000-000000000001';

        $injection = $this->injector->inject(
            '<!doctype html><html><head><title>t</title></head><body>hi</body></html>',
            $build,
        );

        $this->assertTrue($injection->wasInjected());

        $html = $injection->bytes;

        $this->assertSame(1, substr_count($html, '<script defer src="/_/addons/docup.js"></script>'));
        $this->assertSame(1, substr_count($html, '<meta name="docup" content="b='.$build.'">'));

        // Before the close, not after it.
        $this->assertLessThan(strpos($html, '</head>'), strpos($html, '<meta name="docup"'));

        // 🛑 Project- and version-agnostic: the build id is the only identifier
        // present. §8.15.1 — "baking project or version identifiers into HTML
        // would destroy cross-project build reuse (§8.7.9) and make the theme
        // stylesheet project-scoped in the artifact".
        $this->assertStringNotContainsString('project', $injection->bytes);
        $this->assertStringNotContainsString('latest', $injection->bytes);
    }

    /**
     * §8.15.1: the loader path is stable and **not** content-hashed.
     *
     * "Hashing the loader path would orphan chrome on every historical artifact
     * at each upgrade" — and artifacts are immutable (§8.8.1), so there would be
     * no way to fix them except a re-ingest of everything ever published.
     */
    public function test_the_loader_path_carries_no_hash(): void
    {
        $this->assertSame('/_/addons/docup.js', ChromeInjector::LOADER_PATH);
        $this->assertDoesNotMatchRegularExpression('/[0-9a-f]{8,}/', ChromeInjector::LOADER_PATH);

        // And it is under §7.3's reserved namespace, so no project can mount a
        // path that shadows it.
        $this->assertStringStartsWith('/_/', ChromeInjector::LOADER_PATH);
    }

    /**
     * 🛑 §8.15.3: "a byte-level, **case-insensitive** search tolerating
     * whitespace before the delimiter (`</head\s*>`), because `</HEAD>` and
     * `</head >` are both legal and both occur, and a naive fixed-string search
     * produces false failures on valid documents."
     */
    #[DataProvider('headSpellings')]
    public function test_it_tolerates_every_legal_spelling_of_the_delimiter(string $close): void
    {
        $injection = $this->injector->inject(
            '<html><head><title>t</title>'.$close.'<body>hi</body></html>',
            'build-1',
        );

        $this->assertSame(InjectionOutcome::Injected, $injection->outcome, "for [{$close}]");
        $this->assertStringContainsString('name="docup"', $injection->bytes);
    }

    /** @return \Generator<string, array{0: string}> */
    public static function headSpellings(): \Generator
    {
        yield 'lowercase' => ['</head>'];
        yield 'uppercase' => ['</HEAD>'];
        yield 'mixed case' => ['</Head>'];
        yield 'trailing space' => ['</head >'];
        yield 'trailing newline' => ["</head\n>"];
        yield 'trailing tab' => ["</head\t>"];
    }

    /** The FIRST close, when a document somehow contains two. */
    public function test_it_injects_before_the_first_delimiter_only(): void
    {
        $injection = $this->injector->inject(
            '<html><head></head><body><pre>&lt;/head&gt;</pre></body></html>',
            'build-1',
        );

        $this->assertSame(1, substr_count($injection->bytes, 'name="docup"'));
    }

    /**
     * 🛑 §8.15.3: injection must not parse or re-serialise third-party markup.
     *
     * Asserted as a property of the output: everything outside the insertion
     * point is byte-identical. A parser would normalise attributes, close
     * optional tags and reorder nothing predictably — and normalising
     * attacker-supplied markup changes what a browser renders in ways nobody
     * reviewed.
     */
    public function test_it_changes_nothing_but_the_insertion_point(): void
    {
        $original = '<!DOCTYPE HTML><html lang=en><head><meta charset=utf-8>'
            .'<title>Untidy &amp; unclosed<p>deliberately malformed</head><body>x';

        $injection = $this->injector->inject($original, 'build-1');

        $tags = '<script defer src="/_/addons/docup.js"></script><meta name="docup" content="b=build-1">';

        $this->assertSame($original, str_replace($tags, '', $injection->bytes));
    }

    // ------------------------------------------------- the stub exclusion

    /**
     * 🛑 §8.15.3 and ADR 0002: Antora's site-root redirect stub is recorded and
     * does **not** warn.
     *
     * ADR 0002 measured "51 of 52 HTML files across all seven generators
     * injected (98.1%); **100% of content pages**, the single miss being
     * Antora's headless site-root redirect stub."
     */
    #[DataProvider('navigationalStubs')]
    public function test_a_navigational_stub_is_recorded_without_warning(string $html): void
    {
        $injection = $this->injector->inject($html, 'build-1');

        $this->assertSame(InjectionOutcome::SkippedStub, $injection->outcome);
        $this->assertFalse($injection->outcome->raisesWarning());
        $this->assertFalse($injection->outcome->forcesApiOnly());

        // And the bytes are stored unchanged: §8.15.4 publishes a
        // non-injectable artifact rather than refusing it.
        $this->assertSame($html, $injection->bytes);
    }

    /** @return \Generator<string, array{0: string}> */
    public static function navigationalStubs(): \Generator
    {
        yield 'meta refresh' => ['<meta http-equiv="refresh" content="0; url=./en/latest/">'];
        yield 'meta refresh unquoted' => ['<meta http-equiv=refresh content="0; url=/x/">'];
        yield 'location assignment' => ['<script>location = "./en/latest/"</script>'];
        yield 'location.replace' => ['<script>location.replace("./en/latest/")</script>'];
        yield 'location.href' => ['<script>location.href = "/x/"</script>'];
    }

    /**
     * 🛑 And a real page that merely mentions a redirect still warns.
     *
     * The exemption must not swallow the thing it was carved out of: a
     * documentation page about redirects is a page a reader sees, and it needs
     * chrome.
     */
    public function test_a_real_page_mentioning_a_redirect_is_not_a_stub(): void
    {
        $html = '<html><body><h1>Redirects</h1>'
            .'<p>Use a meta http-equiv="refresh" tag, or assign to location = "/elsewhere/". '
            .'Both are supported, and this paragraph exists so the document has prose in it '
            .'the way a real documentation page does.</p></body></html>';

        $injection = $this->injector->inject($html, 'build-1');

        $this->assertSame(InjectionOutcome::RefusedNoHead, $injection->outcome);
        $this->assertTrue($injection->outcome->raisesWarning());
    }

    // --------------------------------------------- the non-injectable classes

    /** §8.15.4: no `</head>` element at all. */
    public function test_a_document_with_no_head_is_refused(): void
    {
        $injection = $this->injector->inject(
            '<html><body>'.str_repeat('Real prose that a reader would see. ', 10).'</body></html>',
            'build-1',
        );

        $this->assertSame(InjectionOutcome::RefusedNoHead, $injection->outcome);
    }

    /**
     * 🛑 §8.15.4: non-UTF-8 is **refused rather than injected**.
     *
     * "even though inserting ASCII bytes would appear to work, because the
     * document's own charset declaration cannot be trusted without parsing and
     * a mis-declared charset is an XSS vector."
     */
    public function test_a_non_utf8_document_is_refused_even_though_injection_would_appear_to_work(): void
    {
        // A lone 0x93 — valid Shift-JIS, invalid UTF-8. The document has a
        // perfectly good </head>, so the ONLY reason to refuse is the encoding.
        $html = "<html><head><meta charset=\"shift_jis\"></head><body>\x93\x4Ex</body></html>";

        $this->assertSame(1, preg_match('#</head>#', $html), 'the fixture must have a head to close');

        $injection = $this->injector->inject($html, 'build-1');

        $this->assertSame(InjectionOutcome::RefusedNonUtf8, $injection->outcome);
        $this->assertSame($html, $injection->bytes, 'the bytes must be stored unchanged');
    }

    /** §8.15.4: over the configured byte ceiling. */
    public function test_an_oversized_document_is_refused(): void
    {
        $small = new ChromeInjector(maxBytes: 512);

        $injection = $small->inject(
            '<html><head></head><body>'.str_repeat('x', 1024).'</body></html>',
            'build-1',
        );

        $this->assertSame(InjectionOutcome::RefusedTooLarge, $injection->outcome);
    }

    /**
     * §8.15.4: client-side-routed output is **not** a non-injectable class.
     *
     * "a measured SPA shell carries a conventional `</head>` and injects
     * cleanly. The SPA risk is a runtime one — client-side routing may replace
     * the DOM after injection — and it is §8.15.5's closed shadow root that
     * addresses it, not ingest (ADR 0002)."
     */
    public function test_a_single_page_app_shell_injects_cleanly(): void
    {
        $injection = $this->injector->inject(
            '<html><head><script src="/app.js"></script></head><body><div id="root"></div></body></html>',
            'build-1',
        );

        $this->assertSame(InjectionOutcome::Injected, $injection->outcome);
    }

    // ------------------------------------------------------------- coverage

    /** §8.15.3: coverage recorded, with the warning excluding stubs. */
    public function test_coverage_separates_the_record_from_the_warning(): void
    {
        $coverage = new InjectionCoverage;

        $coverage->record('html/index.html', InjectionOutcome::Injected);
        $coverage->record('html/a.html', InjectionOutcome::Injected);
        $coverage->record('html/stub.html', InjectionOutcome::SkippedStub);
        $coverage->record('html/broken.html', InjectionOutcome::RefusedNoHead);

        $this->assertSame(4, $coverage->documents());
        $this->assertSame(2, $coverage->injected());
        $this->assertSame(50.0, $coverage->percentage());

        $warning = $coverage->warning();

        $this->assertNotNull($warning);
        $this->assertSame(['html/broken.html'], $warning['files'], 'the stub must not appear in the warning');

        // 🛑 And it IS in the record. §8.15.3: stubs "stay in the audit record
        // but must not raise a warning".
        $record = $coverage->toArray();

        $this->assertSame(['html/stub.html'], $record['stub_samples']);
        $this->assertSame(ChromeInjector::VERSION, $record['injector_version']);
    }

    public function test_a_build_of_only_stubs_raises_no_warning(): void
    {
        $coverage = new InjectionCoverage;

        $coverage->record('html/index.html', InjectionOutcome::SkippedStub);

        $this->assertNull($coverage->warning(), 'an Antora site root must not warn on every build forever');
        $this->assertFalse($coverage->forcesApiOnly());
        $this->assertSame('injected', $coverage->appliedChromeMode('injected'));
    }

    /** 🛑 §8.15.4: one uninjectable document falls the whole build back. */
    public function test_one_uninjectable_document_forces_api_only_for_the_build(): void
    {
        $coverage = new InjectionCoverage;

        for ($i = 0; $i < 99; $i++) {
            $coverage->record("html/p{$i}.html", InjectionOutcome::Injected);
        }

        $coverage->record('html/odd.html', InjectionOutcome::RefusedNonUtf8);

        // Per build, not per file: a reader moving between pages must not find
        // the version switcher appearing and disappearing.
        $this->assertTrue($coverage->forcesApiOnly());
        $this->assertSame('api_only', $coverage->appliedChromeMode('injected'));
    }

    /** A project that chose `off` or `api_only` keeps its choice (§8.15.7). */
    public function test_a_deliberate_project_mode_is_not_overridden(): void
    {
        $coverage = new InjectionCoverage;
        $coverage->record('html/odd.html', InjectionOutcome::RefusedNoHead);

        $this->assertSame('off', $coverage->appliedChromeMode('off'));
        $this->assertSame('api_only', $coverage->appliedChromeMode('api_only'));
    }

    // ------------------------------------------- through the real ingestor

    public function test_an_ingested_tree_carries_the_tags_in_storage(): void
    {
        $buildId = Uuid::v7();

        $archive = (new ArchiveWriter)
            ->add('html/index.html', '<html><head></head><body>hi</body></html>')
            ->add('html/assets/site.css', "body{color:#222}\n")
            ->toTarGz($this->fixtures.'/tree.tar.gz');

        $result = $this->ingestor->ingest($buildId, $archive);

        $stored = (string) Storage::disk('artifacts')
            ->get('builds/'.Uuid::toText($buildId).'/html/index.html');

        $this->assertStringContainsString('name="docup"', $stored);
        $this->assertStringContainsString(Uuid::toText($buildId), $stored);

        /*
         * 🛑 The manifest digest is of the bytes that were STORED, not of the
         * bytes the archive supplied. §8.9.12 derives the strong ETag from this
         * digest — a digest of the pre-injection bytes would make every injected
         * document's ETag wrong, in the direction that serves stale content from
         * a shared cache.
         */
        $entry = $result->manifest->get('html/index.html');

        $this->assertNotNull($entry);
        $this->assertSame(hash('sha256', $stored), $entry['sha256']);
        $this->assertSame(strlen($stored), $entry['bytes']);

        // The stylesheet is untouched.
        $css = (string) Storage::disk('artifacts')
            ->get('builds/'.Uuid::toText($buildId).'/html/assets/site.css');

        $this->assertSame("body{color:#222}\n", $css);

        $this->assertSame(1, $result->coverage->documents());
        $this->assertSame(1, $result->coverage->injected());
    }

    // ------------------------------------------------ §8.15.10, compressed

    /**
     * 🛑 §8.15.10: "A pre-compressed HTML artifact MUST be decompressed,
     * injected and recompressed at ingest, or refused with a stable error
     * identifier."
     */
    public function test_a_precompressed_document_is_decompressed_injected_and_recompressed(): void
    {
        $buildId = Uuid::v7();
        $plain = '<html><head></head><body>compressed</body></html>';

        $archive = (new ArchiveWriter)
            ->add('html/index.html', '<html><head></head><body>hi</body></html>')
            ->add('html/page.html.gz', (string) gzencode($plain, 9))
            ->toTarGz($this->fixtures.'/precompressed.tar.gz');

        $this->ingestor->ingest($buildId, $archive);

        $stored = (string) Storage::disk('artifacts')
            ->get('builds/'.Uuid::toText($buildId).'/html/page.html.gz');

        // Still gzip, so the edge can serve it as a sidecar.
        $this->assertTrue(str_starts_with($stored, "\x1f\x8b"), 'the sidecar must stay compressed');

        $decompressed = (string) gzdecode($stored);

        $this->assertStringContainsString('name="docup"', $decompressed);
        $this->assertStringContainsString('compressed', $decompressed);
    }

    /** §8.15.10's other half: refused with a stable identifier. */
    public function test_an_undecompressable_sidecar_is_refused_with_a_stable_code(): void
    {
        $archive = (new ArchiveWriter)
            ->add('html/index.html', '<html><head></head><body>hi</body></html>')
            ->add('html/page.html.gz', 'this is not gzip at all')
            ->toTarGz($this->fixtures.'/badgz.tar.gz');

        try {
            $this->ingestor->ingest(Uuid::v7(), $archive);
            $this->fail('an undecompressable sidecar was accepted');
        } catch (IngestRejected $rejection) {
            $this->assertSame('contract.compressed_html_refused', $rejection->rejection->value);
        }
    }

    /**
     * 🛑 An `.html` file whose bytes are gzip is refused, not stored.
     *
     * §8.15.10 permits two dispositions and "stored as though it were HTML" is
     * neither: the serving path would hand a reader gzip bytes under
     * `text/html`, which renders as nothing at all.
     */
    public function test_an_html_file_containing_gzip_is_refused(): void
    {
        $archive = (new ArchiveWriter)
            ->add('html/index.html', '<html><head></head><body>hi</body></html>')
            ->add('html/mislabelled.html', (string) gzencode('<html><head></head><body>x</body></html>', 9))
            ->toTarGz($this->fixtures.'/mislabelled.tar.gz');

        try {
            $this->ingestor->ingest(Uuid::v7(), $archive);
            $this->fail('a gzip-bodied .html file was accepted');
        } catch (IngestRejected $rejection) {
            $this->assertSame('contract.compressed_html_refused', $rejection->rejection->value);
        }
    }
}
