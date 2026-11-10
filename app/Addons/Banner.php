<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Addons;

/**
 * One notification banner, as the payload carries it.
 *
 * 🛑 **Structured, with no sentence in it.** §8.14.3 requires chrome content to
 * be "structured data — navigation links, footer links, an announcement with a
 * tiny inline-tag allowlist, and homepage blocks from a registry — never free
 * HTML", and a banner is chrome content. So this carries a key, a tone and an
 * optional target, and the runtime renders the text from `lang/`.
 *
 * A payload that carried the rendered sentence would also be a payload a
 * `chrome_mode: api_only` consumer could not localise — §8.15.2 makes this the
 * only source of request-scoped data, so the shape has to serve both the
 * built-in runtime and somebody else's.
 */
final readonly class Banner
{
    /**
     * @param  string|null  $href  where the banner sends the reader, origin-relative,
     *                             or null when there is nowhere to send them
     * @param  array<string, string>  $values  substitutions for the `lang/` string,
     *                                         pre-resolved and never a URL
     */
    public function __construct(
        public BannerKind $kind,
        public ?string $href = null,
        public array $values = [],
    ) {}

    /**
     * @return array{kind: string, key: string, tone: string, href: string|null, values: array<string, string>}
     */
    public function toArray(): array
    {
        return [
            'kind' => $this->kind->value,
            'key' => $this->kind->translationKey(),
            'tone' => $this->kind->tone(),
            'href' => $this->href,
            'values' => $this->values,
        ];
    }
}
