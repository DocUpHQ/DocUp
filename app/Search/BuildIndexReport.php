<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * What indexing one build did.
 *
 * 🛑 `$reused` is exit criterion 5's measurement, and it is a boolean rather
 * than an inference from the counts: "a reused build is indexed **once**" is a
 * claim about whether the artifact was read, and a pass that re-extracted and
 * upserted would produce identical row counts. See {@see IndexOutcome} for the
 * same point made about a whole pass.
 */
final readonly class BuildIndexReport
{
    public function __construct(
        public bool $reused,
        public int $generation,
        public int $sections,
        public int $skipped,
    ) {}
}
