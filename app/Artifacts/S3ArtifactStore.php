<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

/**
 * Artifacts in an S3-compatible object store (§11.1, §17 Phase 03).
 *
 * The same interface and the same key construction as the local driver; §17
 * asks for both "behind the same interface" so that an installation can move
 * from one to the other without touching the ingestor, the publisher or the
 * serving edge.
 */
final class S3ArtifactStore extends FilesystemArtifactStore
{
    public function driver(): string
    {
        return 's3';
    }

    /**
     * 🛑 Deliberately a no-op, with the reason recorded.
     *
     * Real immutability on S3 is **Object Lock**, which is a property of the
     * bucket rather than of a request: it must be enabled at bucket creation
     * and cannot be turned on afterwards. DocUp cannot set it from here, and
     * attempting a per-object retention header against a bucket without Object
     * Lock fails on AWS and is silently ignored by much S3-compatible
     * software — so a plausible-looking implementation here would be worse than
     * nothing, because it would read as a guarantee that is not in force.
     *
     * So the write-once guarantee on this driver is the refusal in
     * {@see FilesystemArtifactStore::put()}, and Object Lock is an operator
     * decision documented in the deployment guide. `docup:doctor` reporting
     * whether the bucket has it is owed, and is recorded in the build log
     * rather than implied by an empty method.
     */
    protected function enforceImmutability(string $key): void
    {
        // See the docblock. Nothing to do that would be true.
    }
}
