<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * One search document, as §8.16.3 defines it: "One search document per HTML
 * **section** (heading anchor)".
 *
 * 🛑 **Build-relative, with no URL anywhere in it.** §8.16.5: documents are
 * "keyed to `build_id` and a path **relative to the build**, never to an
 * absolute URL, with result URLs computed at query time from the manifest's
 * mount table". So this object carries `path` and `anchor` and has no idea
 * which project, which version or which host will serve it — which is exactly
 * what lets one extraction serve every project that mounts the build.
 *
 * The temptation is to put the URL here while the extractor still has the
 * mount in hand. Taking it would make a reused build's documents wrong for
 * every project but the first, and wrong invisibly: the hit would be real, the
 * title correct and the link somebody else's.
 */
final readonly class Section
{
    /**
     * @param  string  $path  relative to the build's `html/` root, e.g.
     *                        `guide/index.html`
     * @param  string|null  $anchor  the heading's own `id`, or null for the
     *                               page-level section before the first heading
     * @param  string  $title  the section's own heading text
     * @param  string  $headingPath  §8.16.3's "nested title": the ancestor
     *                               headings, outermost first, joined with
     *                               {@see self::HEADING_SEPARATOR}
     * @param  string  $pageTitle  the page's own `<h1>` or `<title>`
     * @param  string  $content  the section's visible text, navigation and
     *                           anchor links already stripped
     * @param  int  $rank  §8.16.3's −10…+10, clamped by
     *                     {@see SearchRanking::clamp()}
     * @param  int  $position  document order within the page
     */
    public function __construct(
        public string $path,
        public ?string $anchor,
        public string $title,
        public string $headingPath,
        public string $pageTitle,
        public string $content,
        public int $rank = 0,
        public int $position = 0,
    ) {}

    /** §8.16.3's nested-title separator, in the stored value and in the UI. */
    public const string HEADING_SEPARATOR = ' › ';

    /**
     * Whether this section is worth storing at all.
     *
     * A heading with no text under it is a real thing in generated
     * documentation — a parent heading whose children carry all the prose — and
     * storing it adds a result that matches the term and shows the reader
     * nothing. It is kept when the **title** carries the information, which is
     * the case a bare parent heading is, and dropped only when both are empty.
     */
    public function isEmpty(): bool
    {
        return trim($this->title) === '' && trim($this->content) === '';
    }
}
