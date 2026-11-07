<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Seo;

/**
 * 🛑 §8.11.6's `robots.txt`, per domain mount.
 *
 * > "Only the canonical mount is indexable; serving aliases and preview
 * > hosts MUST emit `Disallow: /` and `X-Robots-Tag: noindex`."
 *
 * **Why this is per mount and not per project.** §8.10.2 has every verified
 * domain answering 200 — Read the Docs' canonical-plus-301 is rejected
 * because it "makes mandatory requirement G6 decorative" — so the same
 * documentation is genuinely reachable at several hostnames. That is
 * correct for readers and duplicate content for a crawler. The canonical
 * mount is the one that may be indexed; everything else says so twice, in
 * `robots.txt` and in `X-Robots-Tag`, because the two are read by different
 * things at different times: `robots.txt` stops the fetch, the header stops
 * the indexing of a page fetched before the file was read or through a link
 * that bypassed it.
 *
 * 🛑 `Disallow: /` is **not** a privacy control and must never be mistaken
 * for one. It is a request, honoured by well-behaved crawlers and by
 * nobody else. Access is §12's, and a private project is private whatever
 * this file says.
 */
final readonly class RobotsTxt
{
    /**
     * @param  bool  $indexable  `domain_mounts.is_indexable`, which §8.10.2
     *                           derives from the mode — so this is the
     *                           canonical mount, and not a serving alias or
     *                           a preview host
     * @param  string|null  $sitemapUrl  absolute, or null when the mount has
     *                                   nothing to offer a crawler
     */
    public static function render(bool $indexable, ?string $sitemapUrl): string
    {
        if (! $indexable) {
            /*
             * 🛑 No `Sitemap:` line on a non-indexable mount. Offering one
             * would be an invitation to crawl the very URLs the line above
             * just asked a crawler to leave alone — and some crawlers read
             * `Sitemap:` even when they honour `Disallow`.
             */
            return "User-agent: *\nDisallow: /\n";
        }

        $lines = [
            'User-agent: *',
            'Allow: /',
            '',
            /*
             * §7.3 reserves `/_/` and nothing under it is publicly
             * cacheable. Those paths are request-scoped — search, addons,
             * cross-reference resolution — so a crawler walking them
             * generates work and indexes nothing worth having.
             */
            'Disallow: /_/',
        ];

        if ($sitemapUrl !== null) {
            $lines[] = '';
            $lines[] = 'Sitemap: '.$sitemapUrl;
        }

        return implode("\n", $lines)."\n";
    }
}
