<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

/**
 * The §8.8.2 ingest ceilings, resolved once per ingest.
 *
 * A value object rather than `config()` calls scattered through the ingestor,
 * for one reason that matters: the caps must not change **during** an ingest.
 * Read lazily, a cache flush or a config reload midway through a 50,000-file
 * tree would mean the first half was validated against one ceiling and the
 * second half against another, and the rejection — or worse, the acceptance —
 * would be unreproducible.
 *
 * 🛑 These are a defence against a malicious archive, not a commercial limit.
 * §8.8.10's quotas are per organisation and live in the database; these are the
 * same for every tenant on the installation, which is why they come from
 * configuration an operator sets and not from a row a tenant can influence.
 */
final class IngestCaps
{
    public function __construct(
        public readonly int $files,
        public readonly int $totalBytes,
        public readonly int $fileBytes,
        public readonly float $compressionRatio,
        public readonly int $archiveBytes = 1024 * 1024 * 1024,
    ) {}

    /** Build from `config/artifacts.php`, whose defaults are §8.8.2's verbatim. */
    public static function fromConfig(): self
    {
        /**
         * @var array{
         *     files: int,
         *     total_bytes: int,
         *     file_bytes: int,
         *     compression_ratio: float,
         *     archive_bytes: int
         * } $caps
         */
        $caps = config('artifacts.caps');

        return new self(
            files: $caps['files'],
            totalBytes: $caps['total_bytes'],
            fileBytes: $caps['file_bytes'],
            compressionRatio: $caps['compression_ratio'],
            archiveBytes: $caps['archive_bytes'],
        );
    }

    /**
     * A copy with different ceilings, for tests and for the `doctor` report.
     *
     * Exists so the abuse corpus can prove a cap bites without building a 5 GB
     * fixture: §9.4 wants a permanent, cheap, always-run case for each
     * rejection, and a corpus that takes ten minutes is a corpus that gets
     * excluded from CI.
     */
    public function with(
        ?int $files = null,
        ?int $totalBytes = null,
        ?int $fileBytes = null,
        ?float $compressionRatio = null,
        ?int $archiveBytes = null,
    ): self {
        return new self(
            files: $files ?? $this->files,
            totalBytes: $totalBytes ?? $this->totalBytes,
            fileBytes: $fileBytes ?? $this->fileBytes,
            compressionRatio: $compressionRatio ?? $this->compressionRatio,
            archiveBytes: $archiveBytes ?? $this->archiveBytes,
        );
    }
}
