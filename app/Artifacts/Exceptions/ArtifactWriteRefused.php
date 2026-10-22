<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts\Exceptions;

/**
 * A write would have replaced an existing artifact (§8.8.1).
 *
 * 🛑 Fatal rather than a silent overwrite. §8.8.1 makes artifacts write-once
 * and §8.8.5 requires the previously published build to stay "intact and
 * immediately re-selectable" — so an overwrite does not corrupt one build, it
 * destroys the thing rollback exists to return to. Failing the ingest is the
 * cheap outcome.
 */
final class ArtifactWriteRefused extends \RuntimeException
{
    public static function keyExists(string $key): self
    {
        return new self(
            "Refusing to overwrite the existing artifact key [{$key}] (§8.8.1: artifacts are "
            ."write-once).\n\nKeys derive from a build id, so this means the same build ingested "
            .'twice. Mint a new build rather than re-ingesting: the previously published bytes '
            .'are what rollback returns to (§8.8.5).'
        );
    }
}
