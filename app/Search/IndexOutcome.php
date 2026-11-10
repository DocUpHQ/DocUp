<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * What one indexing pass did, for the command, the log and the tests.
 *
 * 🛑 `$buildsReused` is the number exit criterion 5 is measured by. "A reused
 * build is indexed **once** and is searchable from every project that mounts
 * it" is not provable from a row count — two projects, one document set, and
 * the count looks the same whether the extractor ran once or twice and
 * upserted. What proves it is that the second pass **reused** a generation and
 * read no artifact bytes, and that is this field.
 */
final readonly class IndexOutcome
{
    /**
     * @param  int  $generation  the project's new `search_generation`
     * @param  int  $policyGeneration  🛑 the `policy_generation` observed
     *                                 **before** the pass began, which is what
     *                                 §8.12.21's gate is given. See
     *                                 {@see Indexer::indexProject()} for why it
     *                                 is the earlier value and not the later.
     * @param  int  $versions  versions indexed (§8.16.9's three channels)
     * @param  int  $mounts  scope rows written
     * @param  int  $buildsIndexed  builds whose artifacts were read
     * @param  int  $buildsReused  🛑 builds already indexed at this extractor
     *                             version, whose artifacts were **not** read
     * @param  int  $sections  documents in the live generation
     * @param  int  $skipped  pages the extractor declined
     * @param  int  $peakBytes  🛑 §9.2's "search indexer peak memory: bounded
     *                          and declared per driver", measured by
     *                          `memory_get_peak_usage(true)` across the pass
     */
    public function __construct(
        public int $generation,
        public int $policyGeneration,
        public int $versions,
        public int $mounts,
        public int $buildsIndexed,
        public int $buildsReused,
        public int $sections,
        public int $skipped,
        public int $peakBytes,
    ) {}

    /** One line, for the command and the build log. */
    public function summary(): string
    {
        return sprintf(
            'generation %d: %d versions, %d mounts, %d builds indexed, %d reused, %d sections, %d pages skipped, peak %.1f MiB',
            $this->generation,
            $this->versions,
            $this->mounts,
            $this->buildsIndexed,
            $this->buildsReused,
            $this->sections,
            $this->skipped,
            $this->peakBytes / 1048576,
        );
    }
}
