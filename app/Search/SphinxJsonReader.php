<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * §8.16.4's Sphinx route: the `.fjson` pages `sphinx-build -b json` writes.
 *
 * Each page is one file:
 *
 *     { "body": "<section id=\"install\"><h2>Install…", "title": "Install",
 *       "current_page_name": "guide/index", … }
 *
 * `body` is the page's **content fragment with no theme around it** — no
 * sidebar, no breadcrumb, no footer — which is why this route is worth having.
 * §8.16.3's main-content detection is a heuristic over somebody else's
 * template, and here there is no template to be wrong about: the fragment is
 * the content, so it is handed straight to {@see SectionExtractor::fragment()}
 * and the sectioning is the same code the HTML route uses.
 *
 * ## 🛑 DocUp does not run the second build
 *
 * §8.4.5's output contract publishes "anything written to
 * `$DOCUP_OUTPUT/html/`", so a project that wants this route adds a
 * `build.jobs.post_build` step emitting its JSON build into a subdirectory of
 * the HTML output. That is the project's choice and it costs a second
 * `sphinx-build`; this phase does not add it to anybody's pipeline, and the
 * operator documentation says so rather than implying DocUp produces it. A
 * project that does nothing gets §8.16.3's HTML extraction, which is the
 * shipped behaviour for every generator.
 *
 * ## 🛑 Why `globalcontext.json` has to be there
 *
 * A bare scan for `*.fjson` would also fire on a project **documenting** the
 * JSON builder — a tutorial with a sample `.fjson` in it, which is exactly the
 * kind of file Sphinx's own documentation ships. `globalcontext.json` beside
 * them is what a real JSON build always writes and a sample never does, so the
 * marker is required and the directory holding it is the only one scanned.
 */
final readonly class SphinxJsonReader
{
    /** The most pages read from one build. */
    public const int MAX_PAGES = 20_000;

    /** The largest single `.fjson` decoded. */
    public const int MAX_PAGE_BYTES = 4 * 1024 * 1024;

    public function __construct(private SectionExtractor $extractor) {}

    /**
     * Read the JSON build, or null when there is none.
     *
     * @return list<Section>|null
     */
    public function read(BuildFiles $files, SearchRanking $ranking): ?array
    {
        $root = $this->jsonRoot($files);

        if ($root === null) {
            return null;
        }

        $published = [];

        foreach ($files->documents() as $document) {
            $published[$document] = true;
        }

        $sections = [];
        $pages = 0;

        foreach ($files->paths() as $manifestPath) {
            if ($pages >= self::MAX_PAGES) {
                break;
            }

            if (! str_starts_with($manifestPath, $root) || ! str_ends_with($manifestPath, '.fjson')) {
                continue;
            }

            if (($files->bytes($manifestPath) ?? 0) > self::MAX_PAGE_BYTES) {
                continue;
            }

            $pages++;

            $page = $this->page($files, $manifestPath);

            if ($page === null) {
                continue;
            }

            [$name, $title, $body] = $page;

            $path = $this->htmlPathFor($name, $published);

            if ($path === null || $ranking->ignores($path)) {
                continue;
            }

            foreach ($this->extractor->fragment($path, $body, $ranking, $title) as $section) {
                $sections[] = $section;
            }
        }

        return $sections === [] ? null : $sections;
    }

    /**
     * The directory holding the JSON build, with its trailing slash, or null.
     *
     * The **first** `globalcontext.json` under `html/`, in manifest order.
     * One build has one JSON output; two would mean a project that ran the
     * builder twice, and indexing both would double every section.
     */
    private function jsonRoot(BuildFiles $files): ?string
    {
        foreach ($files->paths() as $path) {
            if (! str_starts_with($path, BuildFiles::HTML_PREFIX)) {
                continue;
            }

            if (! str_ends_with($path, '/'.StructuredIndex::SPHINX_CONTEXT)) {
                continue;
            }

            return substr($path, 0, strlen($path) - strlen(StructuredIndex::SPHINX_CONTEXT));
        }

        return null;
    }

    /**
     * One `.fjson` page's name, title and body fragment.
     *
     * @return array{0: string, 1: string, 2: string}|null
     */
    private function page(BuildFiles $files, string $manifestPath): ?array
    {
        $raw = $files->raw($manifestPath);

        if ($raw === null || $raw === '') {
            return null;
        }

        $decoded = json_decode($raw, true, 32);
        unset($raw);

        if (! is_array($decoded)) {
            return null;
        }

        $name = $decoded['current_page_name'] ?? null;
        $body = $decoded['body'] ?? null;
        $title = $decoded['title'] ?? null;

        if (! is_string($name) || ! is_string($body) || $name === '') {
            return null;
        }

        /*
         * Sphinx's `title` is HTML — it carries the inline markup of the
         * heading, so a page titled `The ``api`` module` arrives with a
         * `<code>` in it. Stripped to text here rather than stored as markup,
         * because the stored title is what a result list renders and §8.14.3's
         * reasoning applies: structured content, never HTML.
         */
        return [$name, $this->plain(is_string($title) ? $title : ''), $body];
    }

    /**
     * The published HTML page a `current_page_name` corresponds to.
     *
     * 🛑 Resolved **against the manifest** rather than assumed, because the
     * answer depends on the HTML builder the project used and Sphinx has two:
     * `html` writes `guide/index.html` for the document `guide/index`, and
     * `dirhtml` writes `guide/index/index.html`. Guessing one makes every
     * result on a `dirhtml` site a 404, so both candidates are offered to the
     * manifest and the one that was actually published wins.
     *
     * @param  array<string, true>  $published
     */
    private function htmlPathFor(string $name, array $published): ?string
    {
        if (str_contains($name, '..') || str_contains($name, '\\') || str_contains($name, "\0")) {
            return null;
        }

        $name = ltrim($name, '/');

        foreach ([$name.'.html', $name.'/index.html'] as $candidate) {
            if (isset($published[$candidate])) {
                return $candidate;
            }
        }

        return null;
    }

    /** Inline markup out, text in. */
    private function plain(string $html): string
    {
        $text = html_entity_decode(strip_tags($html), ENT_QUOTES | ENT_HTML5, 'UTF-8');

        return mb_substr(trim((string) preg_replace('/\s+/u', ' ', $text)), 0, 500);
    }
}
