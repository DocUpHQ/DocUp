<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

use App\Models\Build;
use App\Models\ProjectVersionManifest;
use App\Support\Uuid;

/**
 * What a pointer flip did (§8.8.4).
 *
 * 🛑 `published: false` is a **success**, not an error. §8.8.4's zero-affected-
 * rows outcome means another build won the race, and this build's artifacts are
 * stored, valid and immediately selectable. The flag exists so a caller cannot
 * read the outcome as a failure by accident: an API returning 500 for a lost
 * race would have a CI pipeline retrying a build that worked.
 */
final class PublishOutcome
{
    /**
     * @param  bool  $published  whether this flip won the compare-and-swap
     * @param  Build|null  $build  null when a rollback target's build row has gone
     * @param  string|null  $previousManifestId  raw 16 bytes; what was being served
     */
    public function __construct(
        public readonly bool $published,
        public readonly ?Build $build,
        public readonly ProjectVersionManifest $manifest,
        public readonly ?string $previousManifestId,
    ) {}

    /** §10.3's state for this outcome, which the build row already carries. */
    public function buildState(): string
    {
        return $this->published ? 'published' : 'success_unpublished';
    }

    /**
     * The API representation.
     *
     * Here rather than in a controller because three endpoints return it, and
     * three copies of a response shape is three places for one of them to drift
     * — §8.21.1 requires an OpenAPI document to validate against live
     * responses, and it cannot if the same outcome renders differently per
     * route.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $build = $this->build;

        return [
            // 🛑 The flag a caller branches on. False means §8.8.4's race was
            // lost, which is a success with a different outcome.
            'published' => $this->published,
            'build' => $build === null ? null : [
                'id' => Uuid::toText($build->id),
                'state' => $build->state,
                'file_count' => $build->file_count,
                'total_bytes' => $build->total_bytes,
            ],
            'manifest' => [
                'id' => Uuid::toText($this->manifest->id),
                'revision' => $this->manifest->revision,
            ],
            'previous_manifest' => $this->previousManifestId === null
                ? null
                : Uuid::toText($this->previousManifestId),
        ];
    }
}
