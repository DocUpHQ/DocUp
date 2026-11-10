<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Addons;

use App\Models\Build;
use App\Models\ProjectVersion;
use App\Serving\ManifestReader;
use App\Support\Uuid;

/**
 * 🛑 Which build a version actually publishes — one answer, one place.
 *
 * ## Why this class exists rather than a query
 *
 * "The newest `builds` row for this version" is the obvious answer and it is
 * **wrong**, which cost a debugging session in Phase 28 and is worth the file.
 * Two builds of one version created in the same millisecond tie on
 * `created_at`, so `orderByDesc('created_at')` returns whichever the database
 * felt like — and the re-ingest job then reported its own output as still
 * stale, while the test asserting the pointer had moved passed for the wrong
 * reason.
 *
 * The authority is §8.8.3's version manifest: `published_manifest_id` is the
 * pointer, and the manifest names the build behind each component mount. So a
 * caller asking "what are readers getting" must go through the pointer, which
 * is also the only answer that stays correct for a rollback (§8.8.5) — a
 * rollback flips the pointer to an **older** build and creates no new row at
 * all, so a newest-row query would report the thing nobody is serving.
 *
 * 🛑 **The primary mount's build**, per §8.7.19: a composed version has several
 * builds and the primary is the one whose HTML is the version's own. The same
 * rule {@see AddonsPayload} applies to §8.15.11's offline formats, for the same
 * reason.
 */
final readonly class PublishedBuild
{
    public function __construct(private ManifestReader $manifests) {}

    /**
     * The primary build's id as canonical text, or null.
     *
     * @param  string|null  $manifestId  raw 16 bytes, as the version or the
     *                                   routing snapshot carries it
     */
    public function idFor(?string $manifestId): ?string
    {
        if ($manifestId === null) {
            return null;
        }

        foreach ($this->manifests->mounts($manifestId) as $mount) {
            if ($mount['is_primary'] && $mount['build_id'] !== null) {
                return $mount['build_id'];
            }
        }

        return null;
    }

    /**
     * The primary build row behind a version's published manifest, or null.
     *
     * 🛑 `withoutGlobalScopes`, like every other serving-path read of a build:
     * the caller may be answering a documentation request, where §8.2.1's
     * tenant comes from the hostname rather than from a session.
     */
    public function forVersion(ProjectVersion $version): ?Build
    {
        $buildId = $this->idFor($version->published_manifest_id);

        if ($buildId === null) {
            return null;
        }

        return Build::withoutGlobalScopes()
            ->whereKey(Uuid::tryToBytes($buildId) ?? str_repeat("\xff", 16))
            ->first();
    }
}
