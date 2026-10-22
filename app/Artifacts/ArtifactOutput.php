<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

/**
 * One format's share of an ingest, shaped for a `build_outputs` row (§10.3).
 *
 * One upload carries the whole of `$DOCUP_OUTPUT` (§8.4.5), so one ingest
 * produces one of these per format directory present — which is exactly what
 * `build_outputs` holds, keyed `UNIQUE (build_id, format)`.
 */
final class ArtifactOutput
{
    /**
     * @param  string  $format  a §10.3 format: `html`, `pdf`, `epub`, `htmlzip`
     * @param  string  $storageKey  the prefix this format's files live under
     * @param  string  $contentSha256  digest over this format's sorted path/digest pairs
     */
    public function __construct(
        public readonly string $format,
        public readonly string $storageKey,
        public readonly int $fileCount,
        public readonly int $totalBytes,
        public readonly string $contentSha256,
    ) {}
}
