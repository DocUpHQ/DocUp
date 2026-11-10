<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * A section under construction, inside {@see SectionExtractor}'s walk.
 *
 * 🛑 Mutable, and that is the point: §9.2 budgets the indexer's peak memory,
 * and the alternative — a readonly {@see Section} rebuilt on every text node —
 * allocates one object and one concatenated string per text node in the
 * document. On a Sphinx API reference that is tens of thousands of allocations
 * per page for a value thrown away immediately.
 *
 * So the text accumulates in an array and is joined once, and the immutable
 * {@see Section} is minted at the end by {@see self::toSection()}. Nothing
 * outside this namespace sees one of these.
 *
 * @internal to {@see SectionExtractor}
 */
final class MutableSection
{
    /** @var list<string> */
    private array $chunks = [];

    /**
     * How many characters have been appended.
     *
     * 🛑 Tracked rather than measured, so the cap is enforced **while**
     * appending. Measuring `implode()`'s length per append is quadratic, and a
     * `singlehtml` build is exactly the input that finds out.
     */
    private int $length = 0;

    public function __construct(
        private readonly ?string $anchor,
        private readonly string $title,
        private readonly string $headingPath,
        private readonly int $position,
    ) {}

    /** Add a text node's data, stopping at the cap. */
    public function append(string $text): void
    {
        if ($this->length >= SectionExtractor::MAX_CONTENT_CHARS) {
            return;
        }

        $this->chunks[] = $text;
        $this->length += strlen($text);
    }

    /**
     * Mint the immutable section, or null when there is nothing worth storing.
     *
     * The whitespace collapse happens **here**, once, over the joined string —
     * not per chunk, because a chunk boundary falls in the middle of a run of
     * whitespace as often as not and collapsing each side separately leaves the
     * run behind.
     */
    public function toSection(string $path, string $pageTitle, int $rank): ?Section
    {
        $content = implode('', $this->chunks);
        $content = str_replace(["\u{00A0}", "\u{200B}", "\u{FEFF}"], ' ', $content);
        $content = trim((string) preg_replace('/\s+/u', ' ', $content));
        $content = mb_substr($content, 0, SectionExtractor::MAX_CONTENT_CHARS);

        $section = new Section(
            path: $path,
            anchor: $this->anchor,
            title: $this->title,
            headingPath: $this->headingPath,
            pageTitle: $pageTitle,
            content: $content,
            rank: SearchRanking::clamp($rank),
            position: $this->position,
        );

        return $section->isEmpty() ? null : $section;
    }
}
