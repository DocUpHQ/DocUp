<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * One write to an engine: a slice of one build's sections.
 *
 * 🛑 A batch and not a build, because of §9.2's one budget this phase is
 * measured against: "search indexer peak memory: bounded and declared per
 * driver", at "5,000 pages across 3 components". A 5,000-page Sphinx site has
 * perhaps 40,000 sections, and the obvious implementation — extract everything,
 * then write everything — holds all of them in PHP at once. So the indexer
 * never has a whole build in memory: it fills a batch, hands it over, and drops
 * it.
 *
 * {@see Indexer::BATCH_SECTIONS} is the slice size and the comment there says
 * why that number.
 */
final readonly class SectionBatch
{
    /**
     * @param  string  $buildId  canonical UUID text
     * @param  int  $buildGeneration  §8.16.7's generation this batch belongs to
     * @param  string  $language  the content's own language
     * @param  ExtractedFrom  $extractedFrom  which route produced these
     * @param  int  $extractorVersion  so a later release can find its own rows
     * @param  list<Section>  $sections
     */
    public function __construct(
        public string $buildId,
        public int $buildGeneration,
        public string $language,
        public ExtractedFrom $extractedFrom,
        public int $extractorVersion,
        public array $sections,
    ) {}

    public function isEmpty(): bool
    {
        return $this->sections === [];
    }

    public function count(): int
    {
        return count($this->sections);
    }
}
