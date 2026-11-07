<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Seo;

use App\Serving\Hreflang;

/**
 * 🛑 §8.11.6's `sitemap.xml`, with §8.11.6's `hreflang`.
 *
 * > "`hreflang` MUST be generated across versions, mounts **and** domains."
 *
 * Phase 16 shipped that computation as an RFC 8288 `Link` header, because
 * P16 was built before P20 and a header was the only surface it had. This
 * is the surface the requirement actually names, and the two read the same
 * {@see Hreflang} — so a reader and a crawler cannot be told
 * different things about where a page's translations live.
 *
 * 🛑 **Hidden versions are omitted**, which is §17's exit criterion for
 * this file and is a §8.6 distinction rather than an access one. P10 makes
 * `active`, `listed`, `published` and `visibility` four independent axes:
 * a version with `listed=false` "still returns 200 by direct URL and is
 * absent from the version list" — so it is reachable on purpose and
 * unadvertised on purpose, and putting it in a sitemap would advertise it.
 * The filtering is the caller's; this class renders what it is given and
 * says what it expects.
 */
final readonly class Sitemap
{
    /**
     * Google's documented ceiling, and the one every other crawler
     * adopted. A larger file is not an error but is read by nobody.
     */
    public const int MAX_URLS = 50_000;

    /**
     * @param  list<SitemapEntry>  $entries  already filtered: no hidden
     *                                       version, no unpublished version,
     *                                       no non-public project
     */
    public static function render(array $entries): string
    {
        $out = '<?xml version="1.0" encoding="UTF-8"?>'."\n";
        $out .= '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"'
            .' xmlns:xhtml="http://www.w3.org/1999/xhtml">'."\n";

        foreach (array_slice($entries, 0, self::MAX_URLS) as $entry) {
            $out .= "  <url>\n";
            $out .= '    <loc>'.self::escape($entry->location)."</loc>\n";

            if ($entry->lastModified !== null) {
                /*
                 * W3C datetime, which is what the sitemap schema asks for.
                 * Seconds, not milliseconds: a crawler compares these and a
                 * precision nobody else emits only invites disagreement.
                 */
                $out .= '    <lastmod>'.$entry->lastModified->toIso8601String()."</lastmod>\n";
            }

            foreach ($entry->alternates as $language => $href) {
                /*
                 * 🛑 `xhtml:link rel="alternate"` is how a sitemap carries
                 * `hreflang`, and the set must be **reciprocal**: every
                 * alternate must list every other, including itself.
                 * {@see \App\Serving\Hreflang} builds the set that way, and
                 * a non-reciprocal set is silently ignored by the one
                 * crawler that reads these most.
                 */
                $out .= '    <xhtml:link rel="alternate" hreflang="'.self::escape($language)
                    .'" href="'.self::escape($href).'"/>'."\n";
            }

            $out .= "  </url>\n";
        }

        return $out.'</urlset>'."\n";
    }

    /**
     * 🛑 Escaped, and the sitemap schema is explicit that a URL in a `<loc>`
     * must be entity-escaped rather than percent-encoded a second time.
     *
     * An unescaped `&` in a query string is the common way a sitemap
     * becomes unparseable — and an unparseable sitemap is discarded whole,
     * so one bad URL loses every other.
     */
    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    }
}
