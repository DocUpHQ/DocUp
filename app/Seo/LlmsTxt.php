<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Seo;

/**
 * 🛑 §8.11.7's AI-agent surfaces.
 *
 * > "AI-agent surfaces MUST be: `llms.txt` and `llms-full.txt` generated at
 * > publish from the navigation tree and section index, plus `.md` siblings
 * > **that a generator already emitted**. Serve-time HTML→Markdown
 * > conversion MUST NOT be implemented (§4.2)."
 *
 * **The emphasis is the whole requirement.** The obvious way to serve
 * Markdown to an agent is to convert HTML on the way out, and §4.2 puts
 * that permanently out of scope — not deferred, out. The reasons are worth
 * restating where somebody might add it "just for `.md`":
 *
 *  - it is a parser and a serialiser on the serving path, which is where
 *    §4.3 says documentation bytes never traverse PHP;
 *  - it produces a *different document* from the one the author wrote, so
 *    an agent quoting it quotes DocUp's reconstruction;
 *  - it is unbounded work driven by an attacker-chosen URL, on a path
 *    §9.3.5 already lists as a DDoS target.
 *
 * So the `.md` siblings served are the ones **a generator emitted** and
 * nothing else, and these two files are built at publish from the
 * navigation tree the manifest already carries.
 *
 * 🛑 `llms.txt` lists; `llms-full.txt` includes. The split is the point of
 * the convention: an agent with a small budget reads the index and fetches
 * what it needs, and one with a large budget reads everything in one
 * request rather than crawling.
 */
final readonly class LlmsTxt
{
    /**
     * A section of the navigation tree, flattened to one level of heading
     * plus its links.
     *
     * @param  list<array{title: string, url: string, description?: string}>  $links
     */
    public static function section(string $heading, array $links): string
    {
        $out = '## '.$heading."\n\n";

        foreach ($links as $link) {
            $out .= '- ['.self::text($link['title']).']('.$link['url'].')';

            if (isset($link['description']) && $link['description'] !== '') {
                $out .= ': '.self::text($link['description']);
            }

            $out .= "\n";
        }

        return $out;
    }

    /**
     * The index.
     *
     * @param  list<array{heading: string, links: list<array{title: string, url: string, description?: string}>}>  $sections
     */
    public static function index(string $title, ?string $summary, array $sections): string
    {
        $out = '# '.self::text($title)."\n";

        if ($summary !== null && $summary !== '') {
            $out .= "\n> ".self::text($summary)."\n";
        }

        foreach ($sections as $section) {
            $out .= "\n".self::section($section['heading'], $section['links']);
        }

        return $out;
    }

    /**
     * The full text: the index, then each document's Markdown in order.
     *
     * 🛑 The bodies are the generator's own `.md` siblings, read from the
     * build. Where a document has none it is **listed and not included** —
     * not converted, not omitted. An agent that finds a link in the index
     * and no body below it can fetch the HTML; one given a reconstruction
     * would not know it was reading one.
     *
     * @param  list<array{heading: string, links: list<array{title: string, url: string, description?: string}>}>  $sections
     * @param  array<string, string>  $bodies  url → the generator's Markdown
     */
    public static function full(string $title, ?string $summary, array $sections, array $bodies): string
    {
        $out = self::index($title, $summary, $sections);

        foreach ($sections as $section) {
            foreach ($section['links'] as $link) {
                $body = $bodies[$link['url']] ?? null;

                if ($body === null) {
                    continue;
                }

                $out .= "\n\n---\n\n";
                $out .= '# '.self::text($link['title'])."\n\n";
                $out .= '<!-- source: '.$link['url']." -->\n\n";
                $out .= rtrim($body)."\n";
            }
        }

        return $out;
    }

    /**
     * 🛑 Markdown control characters in a title are escaped, and a newline
     * ends the entry.
     *
     * A title is author-supplied, it lands inside a `[…]`, and an
     * unescaped `]` would end the link text early — turning the rest of a
     * title into document structure an agent then reads as instructions.
     * This is the same class of problem as HTML injection and the same
     * answer: escape at the boundary where the meaning changes.
     */
    private static function text(string $value): string
    {
        $value = str_replace(["\r\n", "\r", "\n"], ' ', $value);
        $value = preg_replace('/\s+/u', ' ', $value) ?? $value;

        return trim(str_replace(['[', ']', '(', ')'], ['\[', '\]', '\(', '\)'], $value));
    }
}
