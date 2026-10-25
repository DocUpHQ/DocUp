<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Serving;

use App\Serving\Hreflang;
use App\Serving\SnapshotMount;
use App\Serving\SnapshotProject;
use App\Serving\SnapshotVersion;
use App\Serving\VersionUrl;
use PHPUnit\Framework\TestCase;

/**
 * §8.11.6's annotation, and §7.3's path construction behind it.
 *
 * Pure: an alternate set is a function of which languages hold the page and
 * where the canonical mount is, and both are decided before this runs. The
 * existence filter and the canonical lookup have their own tests because they
 * touch manifests and rows; what is left here is the part that must never be
 * wrong and costs nothing to check.
 */
final class HreflangTest extends TestCase
{
    /** 🛑 One language is not a translation, so nothing is annotated. */
    public function test_a_single_language_produces_no_alternates(): void
    {
        $this->assertSame(
            [],
            Hreflang::alternates([['language' => 'en', 'path' => '/en/v2/']], 'https://docs.example'),
        );
    }

    /**
     * 🛑 The set is self-referential.
     *
     * An annotation that omitted the page being served is discarded by every
     * consumer that checks reciprocity, so leaving self out would make the
     * whole set inert rather than merely incomplete.
     */
    public function test_the_served_page_is_in_its_own_alternate_set(): void
    {
        $alternates = Hreflang::alternates([
            ['language' => 'en', 'path' => '/en/v2/guide.html'],
            ['language' => 'ja', 'path' => '/ja/v2/guide.html'],
        ], 'https://docs.example');

        $languages = array_column($alternates, 'hreflang');

        $this->assertContains('en', $languages);
        $this->assertContains('ja', $languages);
    }

    /** `x-default` is the project default version's language. */
    public function test_x_default_points_at_the_default_language(): void
    {
        $alternates = Hreflang::alternates([
            ['language' => 'en', 'path' => '/en/v2/guide.html'],
            ['language' => 'ja', 'path' => '/ja/v2/guide.html'],
        ], 'https://docs.example', defaultLanguage: 'en');

        $this->assertContains(
            ['hreflang' => 'x-default', 'href' => 'https://docs.example/en/v2/guide.html'],
            $alternates,
        );
    }

    /**
     * 🛑 And is omitted rather than guessed when that language's page is
     * missing.
     *
     * A wrong `x-default` sends every unmatched reader to one arbitrary
     * translation, which is §8.6.13's silent fallback wearing a different
     * hat.
     */
    public function test_x_default_is_omitted_when_the_default_language_lacks_the_page(): void
    {
        $alternates = Hreflang::alternates([
            ['language' => 'fr', 'path' => '/fr/v2/guide.html'],
            ['language' => 'ja', 'path' => '/ja/v2/guide.html'],
        ], 'https://docs.example', defaultLanguage: 'en');

        $this->assertSame([], array_filter(
            $alternates,
            static fn (array $a): bool => $a['hreflang'] === 'x-default',
        ));
    }

    /** The header is RFC 8288, one entry per alternate. */
    public function test_the_header_names_every_alternate(): void
    {
        $header = Hreflang::header([
            ['hreflang' => 'en', 'href' => 'https://docs.example/en/v2/'],
            ['hreflang' => 'ja', 'href' => 'https://docs.example/ja/v2/'],
        ]);

        $this->assertSame(
            '<https://docs.example/en/v2/>; rel="alternate"; hreflang="en", '
                .'<https://docs.example/ja/v2/>; rel="alternate"; hreflang="ja"',
            $header,
        );
    }

    /** No alternates, no header — not an empty one. */
    public function test_an_empty_set_produces_no_header(): void
    {
        $this->assertNull(Hreflang::header([]));
    }

    /**
     * 🛑 §7.3's path, built by the one function the resolver itself uses.
     *
     * The three schemes produce three shapes and the extraction would be
     * worthless if they drifted — so the shapes are asserted here as well as
     * through the resolver's own suite.
     */
    public function test_the_version_url_follows_the_scheme(): void
    {
        $version = new SnapshotVersion(
            id: 'v', slug: 'v2', language: 'ja',
            active: true, listed: true, published: true, visibility: 'public',
            publishedManifestId: 'm',
        );

        $this->assertSame('/ja/v2/', VersionUrl::root($this->mount(''), 'lang_and_version', $version));
        $this->assertSame('/v2/', VersionUrl::root($this->mount(''), 'multi_version', $version));
        $this->assertSame('/', VersionUrl::root($this->mount(''), 'single_version', $version));
    }

    /** And it carries the mount prefix and the project prefix, in order. */
    public function test_the_version_url_carries_every_prefix(): void
    {
        $version = new SnapshotVersion(
            id: 'v', slug: 'v2', language: 'ja',
            active: true, listed: true, published: true, visibility: 'public',
            publishedManifestId: 'm',
        );

        $this->assertSame(
            '/projects/sdk/docs/ja/v2/guide.html',
            VersionUrl::document($this->mount('projects/sdk', 'docs'), 'lang_and_version', $version, 'guide.html'),
        );
    }

    private function mount(string $pathPrefix, ?string $urlPrefix = null): SnapshotMount
    {
        return new SnapshotMount(
            id: 'm',
            pathPrefix: $pathPrefix,
            mode: 'canonical',
            mountExposure: 'inherit',
            isIndexable: true,
            project: new SnapshotProject(
                id: 'p',
                slug: 'sdk',
                urlPrefix: $urlPrefix,
                versioningScheme: 'lang_and_version',
                routingEpoch: 1,
                visibility: 'public',
                chromeMode: 'injected',
                defaultVersionId: null,
            ),
        );
    }
}
