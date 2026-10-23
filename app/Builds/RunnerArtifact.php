<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Models\ProjectVersion;

/**
 * The built-in runner's tree, as a {@see PublishSource}.
 *
 * 🛑 It implements the same interface an operator's CI reaches through the
 * §8.21.6 upload API, and it carries no extra capability: the same archive
 * path, the same version, the same ingest. What it carries *more* of is
 * provenance — because DocUp built it and therefore knows the image digest
 * and the pinned SHAs — and §8.5.24's document says so with its `origin`
 * field rather than by having a different shape.
 */
final readonly class RunnerArtifact implements PublishSource
{
    /** @param  array<string, mixed>  $provenance */
    public function __construct(
        private string $archivePath,
        private ProjectVersion $version,
        private ?string $actorId,
        private array $provenance,
    ) {}

    public function archivePath(): string
    {
        return $this->archivePath;
    }

    public function version(): ProjectVersion
    {
        return $this->version;
    }

    public function actorId(): ?string
    {
        return $this->actorId;
    }

    /** @return array<string, mixed> */
    public function provenanceFacts(): array
    {
        return $this->provenance;
    }
}
