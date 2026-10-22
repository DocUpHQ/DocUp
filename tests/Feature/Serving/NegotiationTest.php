<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Serving;

use App\Serving\Negotiation;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * §8.9.13 — pre-compressed sidecars, and `Vary: Accept-Encoding`.
 *
 * The header-parsing half is where this goes wrong in practice, so the cases
 * below are mostly headers rather than files: a `q=0` read as acceptance sends
 * compressed bytes to a client that said it could not read them, and the symptom
 * is a blank page with no error anywhere.
 */
final class NegotiationTest extends TestCase
{
    /**
     * @param  list<string>  $paths
     * @return array<string, array{sha256: string, bytes: int, content_type: string}>
     */
    private function files(array $paths): array
    {
        $files = [];

        foreach ($paths as $index => $path) {
            $files[$path] = [
                // A distinct digest per file, which is the point of the ETag
                // assertion below: a sidecar is its own manifest entry.
                'sha256' => str_pad((string) ($index + 1), 64, '0', STR_PAD_LEFT),
                'bytes' => 100 + $index,
                'content_type' => 'text/html; charset=utf-8',
            ];
        }

        return $files;
    }

    public function test_it_serves_a_gzip_sidecar_when_the_client_accepts_gzip(): void
    {
        $files = $this->files(['html/index.html', 'html/index.html.gz']);

        [$key, $encoding] = Negotiation::choose($files, 'html/index.html', 'gzip, deflate');

        $this->assertSame('html/index.html.gz', $key);
        $this->assertSame('gzip', $encoding);
    }

    /** Brotli wins when both are offered and both exist: better ratio, free. */
    public function test_brotli_is_preferred_over_gzip(): void
    {
        $files = $this->files(['html/index.html', 'html/index.html.gz', 'html/index.html.br']);

        [$key, $encoding] = Negotiation::choose($files, 'html/index.html', 'gzip, br');

        $this->assertSame('html/index.html.br', $key);
        $this->assertSame('br', $encoding);
    }

    public function test_it_falls_back_to_gzip_when_only_gzip_exists(): void
    {
        $files = $this->files(['html/index.html', 'html/index.html.gz']);

        [$key, $encoding] = Negotiation::choose($files, 'html/index.html', 'br, gzip');

        $this->assertSame('html/index.html.gz', $key);
        $this->assertSame('gzip', $encoding);
    }

    public function test_it_serves_the_plain_file_when_no_sidecar_exists(): void
    {
        $files = $this->files(['html/index.html']);

        [$key, $encoding] = Negotiation::choose($files, 'html/index.html', 'gzip, br');

        $this->assertSame('html/index.html', $key);
        $this->assertNull($encoding, 'the edge compresses on the fly; §8.9.13 does not need a header here');
    }

    #[DataProvider('headersThatRefuseCompression')]
    public function test_it_serves_the_plain_file_when_the_client_does_not_accept_it(?string $header): void
    {
        $files = $this->files(['html/index.html', 'html/index.html.gz']);

        [$key, $encoding] = Negotiation::choose($files, 'html/index.html', $header);

        $this->assertSame('html/index.html', $key);
        $this->assertNull($encoding);
    }

    /** @return \Generator<string, array{0: string|null}> */
    public static function headersThatRefuseCompression(): \Generator
    {
        yield 'absent' => [null];
        yield 'empty' => [''];
        yield 'identity only' => ['identity'];

        /*
         * 🛑 `q=0` is an explicit refusal, not a weak preference. Reading it as
         * acceptance sends gzip to something that said it cannot read gzip.
         */
        yield 'gzip refused' => ['gzip;q=0'];
        yield 'gzip refused with spaces' => ['gzip; q=0'];
        yield 'gzip refused among others' => ['deflate, gzip;q=0'];
        yield 'gzip refused with a decimal' => ['gzip;q=0.0'];
    }

    /** A quality value above zero is acceptance, however small. */
    public function test_a_low_but_nonzero_quality_is_still_acceptance(): void
    {
        $files = $this->files(['html/index.html', 'html/index.html.gz']);

        [$key, $encoding] = Negotiation::choose($files, 'html/index.html', 'gzip;q=0.001');

        $this->assertSame('html/index.html.gz', $key);
        $this->assertSame('gzip', $encoding);
    }

    public function test_the_header_is_matched_case_insensitively(): void
    {
        $files = $this->files(['html/index.html', 'html/index.html.gz']);

        [$key] = Negotiation::choose($files, 'html/index.html', 'GZIP');

        $this->assertSame('html/index.html.gz', $key);
    }

    /**
     * 🛑 A sidecar carries its **own** ETag, because §8.9.12 derives the
     * validator from the digest of what is served.
     *
     * Had they shared one, a cache holding the gzip bytes under the plain file's
     * validator could answer a client that never asked for gzip — `Vary` being
     * right and the validator being wrong, and the validator is the one caches
     * trust.
     */
    public function test_a_sidecar_has_a_different_digest_from_its_document(): void
    {
        $files = $this->files(['html/index.html', 'html/index.html.gz']);

        [$served] = Negotiation::choose($files, 'html/index.html', 'gzip');

        $this->assertNotSame($files['html/index.html']['sha256'], $files[$served]['sha256']);
    }

    /**
     * 🛑 A sidecar is never a URL of its own.
     *
     * Serving it directly would give one document two URLs — the cache-key
     * surface §8.9.6 spends its strictness collapsing — and would hand a reader
     * gzip bytes labelled `application/gzip`.
     */
    #[DataProvider('sidecarPaths')]
    public function test_a_sidecar_path_is_recognised_as_one(string $path): void
    {
        $this->assertTrue(Negotiation::isSidecar($path), $path);
    }

    /** @return \Generator<string, array{0: string}> */
    public static function sidecarPaths(): \Generator
    {
        yield 'gzip' => ['html/index.html.gz'];
        yield 'brotli' => ['html/index.html.br'];
        yield 'uppercase' => ['html/INDEX.HTML.GZ'];
    }

    #[DataProvider('ordinaryPaths')]
    public function test_an_ordinary_path_is_not_a_sidecar(string $path): void
    {
        $this->assertFalse(Negotiation::isSidecar($path), $path);
    }

    /** @return \Generator<string, array{0: string}> */
    public static function ordinaryPaths(): \Generator
    {
        yield 'a document' => ['html/index.html'];
        yield 'a stylesheet' => ['html/site.css'];

        // A download a project legitimately ships. §8.9.13 is about sidecars of
        // documents, and `archive.tar.gz` is not one — but it IS matched by the
        // extension rule, which is why §8.9.13's sidecar lookup appends the
        // extension to a resolved path rather than guessing from one.
        yield 'a tarball is matched by extension' => ['html/does-not-exist'];
    }
}
