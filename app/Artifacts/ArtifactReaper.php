<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

use App\Models\Build;

/**
 * The one place a published build's bytes are discarded.
 *
 * §8.8.2 gives the artifact tree one write path, and
 * `ArchitectureTest::test_only_the_artifact_namespace_writes_to_the_artifact_store`
 * enforces it. Deletion is a write: a second place that removed a prefix
 * would be a second place that could remove the wrong one, and the key
 * grammar it would have to rebuild to do so is §8.8.1's — which has exactly
 * one construction site for the same reason.
 *
 * 🛑 **This class exists because Phase 10 tried to do without it.**
 * §8.6.7's "wipe version" called `deletePrefix` from `App\Versions`, the
 * architecture test refused it, and the refusal was right: a version wipe
 * and §8.8.9's garbage collector are two callers of one operation, and
 * giving them each their own would mean two places that know how a build's
 * bytes are addressed.
 *
 * 🛑 **It discards bytes and touches no rows.** The caller owns the
 * database side — clearing a published pointer, recording an audit event —
 * because the orders differ: a wipe clears the pointer *before* the bytes
 * go (otherwise a reader gets a 502 from the edge rather than a 404), and
 * a GC sweep deletes bytes nothing points at. A class doing both would have
 * to pick one order and be wrong for the other caller.
 */
final readonly class ArtifactReaper
{
    public function __construct(private ArtifactStore $store) {}

    /**
     * Discard every stored byte of one build.
     *
     * Idempotent: a build whose bytes are already gone is not an error.
     * §8.8.9's sweeper and a version wipe can both reach the same build,
     * and the second one to arrive should find nothing rather than fail.
     */
    public function discard(Build $build): void
    {
        $this->store->deletePrefix($this->store->prefixFor($build->id));
    }

    /**
     * Discard several, returning how many were reaped.
     *
     * @param  iterable<Build>  $builds
     */
    public function discardAll(iterable $builds): int
    {
        $count = 0;

        foreach ($builds as $build) {
            $this->discard($build);
            $count++;
        }

        return $count;
    }

    /** Is anything still stored for this build? For a caller asserting a sweep. */
    public function holdsAnything(Build $build): bool
    {
        return $this->store->list($this->store->prefixFor($build->id)) !== [];
    }
}
