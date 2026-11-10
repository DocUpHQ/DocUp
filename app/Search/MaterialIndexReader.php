<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

use App\Versions\PageExistence;

/**
 * §8.16.4's Material for MkDocs route: `search/search_index.json`.
 *
 * The file Material's search plugin writes on every build, in the shape it has
 * had since Material 7:
 *
 *     { "config": { … }, "docs": [ { "location": "guide/#install",
 *                                    "title": "Install",
 *                                    "text": "…" }, … ] }
 *
 * One entry per **section**, which is §8.16.3's unit exactly — Material splits
 * on headings for the same reason DocUp does, so the mapping is one to one and
 * there is no re-sectioning to get wrong.
 *
 * ## 🛑 `location` is a URL and the document key is not
 *
 * §8.16.5 keys documents to "a path **relative to the build**, never … an
 * absolute URL", and `location` is a site-root-relative URL in MkDocs' own
 * style: `guide/` with directory URLs on, `guide/index.html` with them off,
 * and either followed by `#anchor`. So it is split at the `#` and the path half
 * is put through §8.9.7's directory→`index.html` mapping — through
 * {@see PageExistence::manifestPathFor()}, which is where Phase 28 put that
 * rule, rather than spelled out a third time here.
 *
 * 🛑 And then it is **checked against the file manifest**. A `location` naming
 * a page the build did not publish is not indexed, whatever it says. That is
 * not tidiness: the file is inside an artifact, a project can commit one by
 * hand, and a hand-written entry with `location: "../../../admin/"` would
 * otherwise mint a search result whose URL points at somebody else's
 * documentation with this project's title on it.
 */
final readonly class MaterialIndexReader
{
    /** The most entries read from one index. */
    public const int MAX_ENTRIES = 200_000;

    /**
     * Read the index, or null when there is none to read.
     *
     * Null means "no structured index here" — absent, oversized, unparseable or
     * empty — and the caller falls back to §8.16.3's HTML extraction. An empty
     * **list** would mean "a structured index saying there is nothing to
     * index", which is a different and much less likely claim, so it is not
     * what absence returns.
     *
     * @return list<Section>|null
     */
    public function read(BuildFiles $files, SearchRanking $ranking): ?array
    {
        $bytes = $files->bytes(StructuredIndex::MATERIAL_PATH);

        if ($bytes === null) {
            return null;
        }

        if ($bytes > StructuredIndex::MAX_INDEX_BYTES) {
            /*
             * §9.2's budget, enforced from the manifest rather than after the
             * read: asking the store for 40 MiB and then deciding not to decode
             * it has already cost the 40 MiB.
             */
            return null;
        }

        $raw = $files->raw(StructuredIndex::MATERIAL_PATH);

        if ($raw === null || $raw === '') {
            return null;
        }

        /*
         * 🛑 `JSON_THROW_ON_ERROR` is deliberately absent and the depth is
         * deliberately small. A hostile file can nest arrays thousands deep to
         * exhaust the parser's stack; a depth of 32 is far beyond this format's
         * three levels and refuses that outright. `null` on failure is the
         * documented fallback, so there is nothing to throw about.
         */
        $decoded = json_decode($raw, true, 32);
        unset($raw);

        if (! is_array($decoded) || ! is_array($decoded['docs'] ?? null)) {
            return null;
        }

        $published = $this->publishedDocuments($files);
        $sections = [];
        $positions = [];
        $read = 0;

        foreach ($decoded['docs'] as $entry) {
            if ($read >= self::MAX_ENTRIES) {
                break;
            }

            $read++;

            if (! is_array($entry)) {
                continue;
            }

            $location = $entry['location'] ?? null;
            $title = $entry['title'] ?? null;
            $text = $entry['text'] ?? null;

            if (! is_string($location)) {
                continue;
            }

            [$path, $anchor] = $this->split($location);

            if ($path === null || ! isset($published[$path])) {
                continue;
            }

            if ($ranking->ignores($path)) {
                continue;
            }

            $position = $positions[$path] ?? 0;
            $positions[$path] = $position + 1;

            $section = new Section(
                path: $path,
                anchor: $anchor,
                title: $this->text($title, 500),
                /*
                 * 🛑 Material's index carries no heading ancestry — its
                 * `title` is the section's own heading and nothing names the
                 * parents. So §8.16.3's nested-title boost is **empty** on this
                 * route rather than guessed at from the location's path
                 * segments, which would put directory names into a field the
                 * UI shows as a breadcrumb of headings.
                 *
                 * Stated rather than silently absent: it is the one thing the
                 * HTML route knows that the structured route does not, and
                 * `ExtractedFrom` is on every row so the asymmetry is visible.
                 */
                headingPath: '',
                pageTitle: $this->pageTitleFor($path, $title, $anchor, $sections),
                content: $this->text($text, SectionExtractor::MAX_CONTENT_CHARS),
                rank: $ranking->rankFor($path),
                position: $position,
            );

            if (! $section->isEmpty()) {
                $sections[] = $section;
            }
        }

        return $sections === [] ? null : $sections;
    }

    /**
     * The build's HTML documents, as a set keyed by build-relative path.
     *
     * @return array<string, true>
     */
    private function publishedDocuments(BuildFiles $files): array
    {
        $set = [];

        foreach ($files->documents() as $path) {
            $set[$path] = true;
        }

        return $set;
    }

    /**
     * A `location` split into a build-relative path and an anchor.
     *
     * @return array{0: string|null, 1: string|null}
     */
    private function split(string $location): array
    {
        /*
         * 🛑 Refuse before normalising, not after. §8.9.6's reasoning applies
         * to a path from inside an artifact as much as to one from a request:
         * a dot segment or a backslash is rejected rather than resolved,
         * because resolving it produces a plausible path and the whole question
         * is whether this file was allowed to name it.
         */
        if (str_contains($location, '..') || str_contains($location, '\\') || str_contains($location, "\0")) {
            return [null, null];
        }

        $hash = strpos($location, '#');
        $anchor = null;

        if ($hash !== false) {
            $anchor = substr($location, $hash + 1);
            $location = substr($location, 0, $hash);
        }

        /* An absolute URL or a protocol-relative one is not this build's page. */
        if (str_starts_with($location, '/') || str_contains($location, '://')) {
            return [null, null];
        }

        /*
         * 🛑 An **empty** location is the site root, not a rejection.
         *
         * Material writes `"location": ""` for the home page — it is the first
         * entry in every `search_index.json` — and the first version of this
         * method refused it along with the absolute URLs. The symptom was a
         * page count one short of the published tree, found by the exit
         * criterion that asserts 5,000 pages rather than "about 5,000": a
         * project's home page was silently unsearchable on every Material site.
         *
         * §8.9.7's mapping handles it from here, turning `''` into
         * `html/index.html` exactly as it does for any other directory URL.
         */

        $query = strpos($location, '?');

        if ($query !== false) {
            $location = substr($location, 0, $query);
        }

        /*
         * §8.9.7's directory→`index.html` mapping, through the one place Phase
         * 28 put it. The `html/` prefix comes back off because §8.16.5's key
         * space is build-relative.
         */
        $manifestPath = PageExistence::manifestPathFor($location);
        $path = substr($manifestPath, strlen(BuildFiles::HTML_PREFIX));

        if ($anchor !== null) {
            $anchor = substr(trim($anchor), 0, 180);

            if ($anchor === '') {
                $anchor = null;
            }
        }

        return [$path, $anchor];
    }

    /**
     * The page's title for a section, from the entry that has no anchor.
     *
     * Material emits the page itself as the **first** entry for a location,
     * with no fragment, so by the time a `#anchor` entry arrives the page title
     * is already in the list. Looking it up backwards is cheap and avoids a
     * second pass over an index that may hold 200,000 entries.
     *
     * @param  list<Section>  $sections
     */
    private function pageTitleFor(string $path, mixed $title, ?string $anchor, array $sections): string
    {
        if ($anchor === null) {
            return $this->text($title, 500);
        }

        for ($i = count($sections) - 1; $i >= 0; $i--) {
            if ($sections[$i]->path !== $path) {
                break;
            }

            if ($sections[$i]->anchor === null) {
                return $sections[$i]->title;
            }
        }

        return '';
    }

    /** A value that should be a string, as one, collapsed and capped. */
    private function text(mixed $value, int $chars): string
    {
        if (! is_string($value)) {
            return '';
        }

        $value = str_replace(["\u{00A0}", "\u{200B}", "\u{FEFF}"], ' ', $value);
        $value = trim((string) preg_replace('/\s+/u', ' ', $value));

        return mb_substr($value, 0, $chars);
    }
}
