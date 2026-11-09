<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Branding\ApiOnlyChrome;
use App\Branding\CascadeLevel;
use App\Branding\Chrome\ChromeContent;
use App\Branding\DeliveredTheme;
use App\Branding\StylesheetCompiler;
use App\Branding\ThemeDelivery;
use App\Branding\ThemeTarget;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\View;

/**
 * 🛑 §8.14.14's "reference example theme", generated rather than written.
 *
 * > "A versioned `chrome_mode: api_only` contract with a **reference example
 * > theme** MUST ship, as the first-class answer to 'can we ship our own
 * > chrome?'. 'Tokens only' loses deals."
 *
 * Two artefacts, from one source:
 *
 * - `resources/themes/api-only-reference.json` — a complete `api_only` payload.
 * - `resources/themes/reference-chrome.html` — that payload rendered as chrome,
 *   which is also the page `npm run axe` checks (§9.5).
 *
 * 🛑 **Generated, and a test asserts the committed files match what DocUp
 * emits.** A reference example that drifts from the implementation is worse
 * than none: an integrator builds against it and finds the difference in
 * production. `ApiOnlyContractTest` regenerates and compares, so drift turns
 * CI red.
 */
final class BrandingReferenceCommand extends Command
{
    protected $signature = 'docup:branding-reference
        {--check : Fail instead of writing when the committed files are out of date}';

    protected $description = 'Generate §8.14.14’s api_only reference payload and its rendered chrome';

    public function handle(): int
    {
        $delivered = ThemeDelivery::make()->deliver(ThemeTarget::installation());

        $payload = self::payloadFor($delivered);
        $html = self::renderFor($delivered);

        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n";

        $failures = 0;

        foreach ([ApiOnlyChrome::REFERENCE_PATH => $json, self::HTML_PATH => $html] as $path => $contents) {
            $absolute = base_path($path);

            if ($this->option('check')) {
                $existing = is_file($absolute) ? (string) file_get_contents($absolute) : null;

                if ($existing !== $contents) {
                    $this->components->error($path.' is out of date; run php artisan docup:branding-reference');
                    $failures++;
                }

                continue;
            }

            if (! is_dir(dirname($absolute))) {
                mkdir(dirname($absolute), 0o755, true);
            }

            file_put_contents($absolute, $contents);
            $this->components->info('Wrote '.$path);
        }

        return $failures === 0 ? self::SUCCESS : self::FAILURE;
    }

    /** Where the rendered reference lives. */
    public const string HTML_PATH = 'resources/themes/reference-chrome.html';

    /**
     * 🛑 The payload, with the **example** chrome content filled in.
     *
     * A fresh installation declares no navigation and no homepage blocks, so
     * the payload for its real theme would show every chrome field as empty —
     * which is a correct payload and a useless reference. So the example
     * content is supplied here, and it is the one place this command invents
     * anything: the tokens, the asset URLs and the scheme are DocUp's real
     * installation defaults.
     *
     * @return array<string, mixed>
     */
    public static function payloadFor(DeliveredTheme $delivered): array
    {
        $payload = $delivered->toPayload();
        $payload['chrome'] = self::exampleChrome()->toPayloadFragment();

        return $payload;
    }

    /** The reference page, rendered from the payload. */
    public static function renderFor(DeliveredTheme $delivered): string
    {
        $payload = self::payloadFor($delivered);
        $theme = $delivered->theme;

        return View::make('branding.reference-chrome', [
            'lang' => 'en',
            'brand' => $theme->serialised('brand.name') ?? 'DocUp',
            'scheme' => $payload['scheme']['default'],
            'schemeToggle' => $payload['scheme']['toggle'],
            'logo' => $payload['assets']['asset.logo'] ?? null,
            'favicon' => isset($payload['assets']['asset.favicon'])
                ? $payload['assets']['asset.favicon']['url']
                : null,
            'navigation' => $payload['chrome']['navigation'],
            'footer' => $payload['chrome']['footer'],
            'announcement' => $payload['chrome']['announcement'],
            'homepage' => $payload['chrome']['homepage'],
            'banner' => $payload['banner'],
            /*
             * 🛑 The theme stylesheet is **compiled**, not read back from the
             * store, so the reference page is a function of the registry at
             * the moment it is generated. Reading the stored file would make
             * the page reflect whichever theme happened to be cached.
             */
            'stylesheet' => (new StylesheetCompiler)->compile($theme),
            'chromeCss' => (string) file_get_contents(base_path('resources/css/chrome.css')),
        ])->render();
    }

    /**
     * The example chrome content: one of every §8.14.3 shape.
     *
     * 🛑 Parsed through {@see ChromeContent}, not hand-written as an array.
     * The reference example is only a reference if it is something the system
     * would accept — and a hand-written payload could show an integrator a
     * shape no tenant could save.
     */
    private static function exampleChrome(): ChromeContent
    {
        return ChromeContent::parse([
            'navigation' => [
                ['label' => 'Guide', 'href' => '/en/latest/'],
                ['label' => 'Reference', 'href' => '/en/latest/reference.html'],
                ['label' => 'Changelog', 'href' => '/en/latest/changelog.html'],
            ],
            'footer' => [
                [
                    'label' => 'Documentation',
                    'links' => [
                        ['label' => 'Getting started', 'href' => '/en/latest/'],
                        ['label' => 'All versions', 'href' => '/'],
                    ],
                ],
                [
                    'label' => 'Project',
                    'links' => [
                        ['label' => 'Source', 'href' => 'https://example.com/source'],
                    ],
                ],
            ],
            'announcement' => [
                'markup' => 'Version <code>2.0</code> is out. <a href="/en/2.0/">Read the notes</a>.',
                'tone' => 'notice',
            ],
            'homepage' => [
                [
                    'type' => 'hero',
                    'heading' => 'Documentation that ships with the code',
                    'body' => 'Every version, every branch, built from the repository it lives in.',
                    'primary_label' => 'Read the guide',
                    'primary_href' => '/en/latest/',
                ],
                [
                    'type' => 'cards',
                    'heading' => 'Start here',
                    'cards' => [
                        ['label' => 'Install', 'href' => '/en/latest/install.html'],
                        ['label' => 'Configure', 'href' => '/en/latest/configure.html'],
                        ['label' => 'Deploy', 'href' => '/en/latest/deploy.html'],
                    ],
                ],
                ['type' => 'search', 'placeholder' => 'Search 1,200 pages'],
                ['type' => 'versions', 'heading' => 'Versions', 'limit' => 5],
                [
                    'type' => 'prose',
                    'heading' => 'About this theme',
                    'body' => 'Every colour, length and family on this page is a branding token. '
                        .'Two projects can look completely different from the same build artifact, '
                        .'because the artifact carries no theme at all.',
                ],
                ['type' => 'callout', 'label' => 'Read the token table', 'href' => '/branding.html'],
            ],
            /*
             * 🛑 §8.14.7 names a 404 page, so the reference payload carries
             * one. The rendered page beside it does NOT show it, and the
             * template says why: a 404 is a different page, and a reference
             * home page that displayed its text would be showing an
             * integrator a layout nobody renders.
             */
            'not_found' => [
                'heading' => 'That page is not here',
                'body' => 'It may have moved with a release. The navigation above still works.',
            ],
        ], CascadeLevel::Installation);
    }
}
