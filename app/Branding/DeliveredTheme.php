<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

use App\Branding\Chrome\ChromeContent;
use App\Models\ThemeAsset;

/**
 * Everything a page or an addons payload needs about one consumer's theme.
 *
 * 🛑 **The JSON shape here is §8.14.14's `api_only` contract.** §8.14.14
 * requires "A versioned `chrome_mode: api_only` contract with a **reference
 * example theme** […] as the first-class answer to 'can we ship our own
 * chrome?'. 'Tokens only' loses deals." So {@see self::toPayload()} is not a
 * convenience serialiser — it is a published interface, and
 * {@see ApiOnlyChrome::VERSION} is the number a consumer pins to.
 */
final readonly class DeliveredTheme
{
    /**
     * @param  array<string, ThemeAsset>  $assets  token name => row
     */
    public function __construct(
        public ResolvedTheme $theme,
        public string $stylesheetUrl,
        public string $contentHash,
        public array $assets,
        public ChromeContent $chrome,
    ) {}

    /**
     * 🛑 §8.14.14's payload, versioned.
     *
     * Structure, not markup. A consumer shipping their own chrome gets the
     * token values, the asset URLs, the structured navigation and footer and
     * the announcement's sanitised inline markup — enough to render a header
     * that matches the tenant's brand without DocUp rendering anything.
     *
     * 🛑 No HTML beyond the announcement's five-element fragment, and that
     * fragment is DocUp's own output rather than a tenant's input
     * ({@see Chrome\InlineMarkup}). A payload that carried a tenant's raw HTML
     * would make every `api_only` consumer responsible for §8.14.8, and most
     * of them would inject it with `innerHTML`.
     *
     * @return array<string, mixed>
     */
    public function toPayload(): array
    {
        return [
            'contract' => ApiOnlyChrome::VERSION,
            'theme' => [
                'hash' => $this->contentHash,
                'stylesheet' => $this->stylesheetUrl,
                'tokens' => $this->tokenPayload(),
            ],
            'assets' => $this->assetPayload(),
            'chrome' => $this->chrome->toPayloadFragment(),
            'scheme' => [
                'default' => $this->theme->serialised('scheme.default') ?? 'system',
                'toggle' => $this->theme->serialised('scheme.toggle') === '1',
            ],
            'banner' => $this->bannerPayload(),
        ];
    }

    /**
     * 🛑 §8.14.16's `frame-ancestors`, for the header builder.
     *
     * Read from the resolved theme rather than from a project column, because
     * §8.14.1's cascade means an organisation may set it once for every project
     * it owns — and a column would have made that a per-project chore.
     */
    public function frameAncestors(): string
    {
        return $this->theme->serialised('security.frame-ancestors') ?? "'self'";
    }

    /**
     * Every token's value in both schemes.
     *
     * 🛑 Asset tokens are excluded: their value is an identifier, and a
     * payload that carried it would invite a consumer to build a URL from it.
     * `assets` carries the URLs DocUp built.
     *
     * @return array<string, array{light: string|null, dark: string|null}>
     */
    private function tokenPayload(): array
    {
        $tokens = [];

        foreach (TokenRegistry::all() as $name => $token) {
            if ($token->type === TokenType::Asset || ! $this->theme->has($name)) {
                continue;
            }

            $tokens[$name] = [
                'light' => $this->theme->serialised($name, ColourScheme::Light),
                'dark' => $this->theme->serialised($name, ColourScheme::Dark),
            ];
        }

        return $tokens;
    }

    /**
     * 🛑 §8.14.11's asset URLs, with their dimensions.
     *
     * The dimensions are there so a consumer can reserve the space before the
     * image loads — a logo that resizes the header on load is a layout shift,
     * and §9.5's accessibility posture includes not moving the page under a
     * reader's cursor. An SVG has none, which is what `width: null` means.
     *
     * @return array<string, array{url: string, media_type: string, width: int|null, height: int|null, alt: string}>
     */
    private function assetPayload(): array
    {
        $payload = [];

        foreach ($this->assets as $name => $asset) {
            $payload[$name] = [
                'url' => ThemeAssets::urlFor($asset),
                'media_type' => $asset->media_type,
                'width' => $asset->width,
                'height' => $asset->height,
                /*
                 * 🛑 The wordmark is the alt text. §9.5 requires WCAG 2.2 AA,
                 * and a logo is a link to the home page — so it needs a name,
                 * and the name a reader needs is the brand's rather than the
                 * file's. The filename is discarded at ingest (§8.14.11), so
                 * there is nothing else it could be.
                 */
                'alt' => $this->theme->serialised('brand.name') ?? '',
            ];
        }

        return $payload;
    }

    /**
     * §8.14.1's version-scoped banner, or null.
     *
     * @return array{text: string, tone: string}|null
     */
    private function bannerPayload(): ?array
    {
        $text = $this->theme->serialised('banner.text');

        if ($text === null || $text === '') {
            return null;
        }

        return ['text' => $text, 'tone' => $this->theme->serialised('banner.tone') ?? 'notice'];
    }
}
