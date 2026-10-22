<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

/**
 * What one successful ingest produced.
 *
 * Returned rather than written to `build_outputs` by the ingestor itself,
 * because §8.8.4 makes publication a compare-and-swap that may **lose** — a
 * build whose ingest succeeded can still terminate as `success_unpublished`. An
 * ingestor that wrote the rows would have decided the outcome of a race it is
 * not party to.
 *
 * Every field maps onto a `builds` or `build_outputs` column (§10.3), which is
 * the point: the caller persists this, and nothing has to be recomputed from
 * the stored bytes to do it.
 */
final class IngestResult
{
    /**
     * @param  string  $buildId  raw 16 bytes
     * @param  string  $archiveFormat  what the upload actually was, for provenance
     * @param  string  $manifestKey  key of the stored `manifest.json`
     * @param  list<ArtifactOutput>  $outputs  one per format directory present
     * @param  string  $contentSha256  digest of the canonical manifest bytes
     */
    public function __construct(
        public readonly string $buildId,
        public readonly string $archiveFormat,
        public readonly string $manifestKey,
        public readonly FileManifest $manifest,
        public readonly array $outputs,
        public readonly int $fileCount,
        public readonly int $totalBytes,
        public readonly string $contentSha256,
    ) {}

    /**
     * The formats this build published, sorted.
     *
     * @return list<string>
     */
    public function formats(): array
    {
        $formats = array_map(static fn (ArtifactOutput $output): string => $output->format, $this->outputs);
        sort($formats, SORT_STRING);

        return $formats;
    }

    public function output(string $format): ?ArtifactOutput
    {
        foreach ($this->outputs as $output) {
            if ($output->format === $format) {
                return $output;
            }
        }

        return null;
    }
}
