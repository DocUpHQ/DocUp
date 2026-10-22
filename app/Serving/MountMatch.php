<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * Which component a path belongs to, and what is left of the path inside it.
 *
 * 🛑 This step exists on its own because each mount resolves to its **own**
 * build, and therefore to its own file manifest. An earlier version looked the
 * file up against one manifest for the whole version, which is correct only
 * while a version has exactly one component — Phase 03's degenerate case. It
 * would have been wrong the moment Phase 13 mounted a second one, and wrong
 * quietly: a path under component B would be looked up in component A's
 * manifest and 404, or worse, hit a same-named file and serve the wrong one.
 *
 * Splitting it also keeps the resolver pure. The caller loads the matched
 * build's manifest between the two calls, so the one storage read is visible
 * where it happens rather than hidden behind a resolver that fetches.
 */
final class MountMatch
{
    /**
     * @param  string  $mountPath  '' for the primary mount at the version root
     * @param  string|null  $buildId  null when the manifest names no build for
     *                                this mount, which §10.4 permits
     * @param  string  $within  the path relative to the component, no leading slash
     */
    public function __construct(
        public readonly string $mountPath,
        public readonly ?string $buildId,
        public readonly string $within,
    ) {}
}
