<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * One matched document, as an engine returns it: build-keyed, with no URL.
 *
 * 🛑 §8.16.5 puts the URL computation at query time and outside the engine, so
 * a driver's job ends here. {@see SearchUrls} turns this plus a
 * {@see ScopeFact} into the {@see SearchResult} a surface renders — and because
 * that is one hit to many facts, a reused build's section becomes one result
 * per mounting project rather than one result with a guessed URL.
 */
final readonly class DocumentHit
{
    /**
     * @param  string  $buildId  canonical UUID text
     * @param  int  $buildGeneration  the generation matched
     * @param  string  $path  relative to the build's `html/` root
     * @param  float  $score  the driver's own relevance, already including
     *                        §8.16.3's boosts and the per-page rank. Comparable
     *                        **within one driver's result set only**: MySQL's
     *                        relevance is an unbounded IDF sum and
     *                        Meilisearch's is a ranking-rule ordering, so
     *                        nothing may compare these across engines or assert
     *                        an absolute value. Tests assert *order*, which is
     *                        the thing both engines owe.
     */
    public function __construct(
        public string $buildId,
        public int $buildGeneration,
        public string $path,
        public ?string $anchor,
        public string $title,
        public string $headingPath,
        public string $pageTitle,
        public string $content,
        public int $rank,
        public float $score,
    ) {}
}
