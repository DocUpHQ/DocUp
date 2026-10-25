<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

use App\Artifacts\ArtifactStore;
use App\Artifacts\FileManifest;
use App\Auth\OrganisationContext;
use App\Support\Uuid;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

/**
 * Reads the two manifests the serving path needs (§8.8.3, §8.4.18).
 *
 * There are two, and they are easy to confuse:
 *
 * - The **version manifest** (§8.8.3) is a database row naming the component
 *   mounts a version serves and the build behind each. It is what
 *   `project_versions.published_manifest_id` points at.
 * - The **file manifest** (§8.4.18) is `manifest.json` in the artifact store,
 *   mapping each path to its sha256, size and content type. There is one per
 *   build.
 *
 * 🛑 Both are **immutable**, which is what makes caching them safe rather than
 * merely fast. §10.4 forbids updating a manifest row — a change is a new
 * revision — and §8.8.1 makes artifacts write-once. So a cache entry keyed on a
 * manifest id or a build id can never be stale, and needs no epoch and no
 * invalidation. §10.8's `serving_epoch` has maximum staleness 0 for exactly this
 * reason: the pointer moves, the thing pointed at never does.
 *
 * 🛑 This class reads the file manifest through {@see ArtifactStore}, never with
 * a file function, and an architecture test forbids a file function anywhere in
 * `App\Serving`. The manifest is metadata DocUp wrote, not documentation — but
 * the boundary is kept absolute, because "it is only metadata" is how the first
 * documentation byte ends up in PHP.
 */
final class ManifestReader
{
    public function __construct(
        private readonly ArtifactStore $store,
        private readonly OrganisationContext $context,
    ) {}

    /**
     * The component mounts a version manifest names.
     *
     * 🛑 `is_primary` is carried because §8.7.19 needs it: "only the
     * **primary** component mount MAY emit `pdf`, `epub` and `htmlzip`."
     * `Publisher` has written the flag into `mounts_json` since Phase 03 and
     * this reader dropped it, so the downloads endpoint would have had to
     * guess — and the guess available today, "the mount at the version root",
     * is right only while there is exactly one mount. Reading the flag costs
     * nothing and stops being a guess in Phase 13.
     *
     * @param  string  $manifestId  raw 16 bytes
     * @return list<array{mount_path: string, build_id: string|null, is_primary: bool}>
     */
    public function mounts(string $manifestId): array
    {
        /** @var list<array{mount_path: string, build_id: string|null, is_primary: bool}> */
        return Cache::rememberForever(
            'manifest:mounts:'.bin2hex($manifestId),
            fn (): array => $this->loadMounts($manifestId),
        );
    }

    /**
     * One build's file manifest, as a path => entry map.
     *
     * @param  string  $buildIdText  canonical UUID text, as the manifest stores it
     * @return array<string, array{sha256: string, bytes: int, content_type: string}>
     */
    public function files(string $buildIdText): array
    {
        /** @var array<string, array{sha256: string, bytes: int, content_type: string}> */
        return Cache::rememberForever(
            'manifest:files:'.$buildIdText,
            fn (): array => $this->loadFiles($buildIdText),
        );
    }

    /**
     * The storage key for a manifest path inside one build.
     *
     * 🛑 Here rather than on {@see FileOutcome}, because §8.8.1's prefix has
     * exactly **one** construction site and an architecture test counts them.
     * `FileOutcome` built it until that test caught the second site — which is
     * how a slug reaches a storage key: not by anyone deciding to put one
     * there, but by a second place that assembles the path and later grows a
     * convenience.
     *
     * This class is allowed to ask because it already holds the store. It asks
     * rather than concatenating, so the grammar still lives in one place.
     *
     * @param  string  $buildIdText  canonical UUID text, as the manifest stores it
     * @param  string  $manifestPath  e.g. `html/index.html`
     */
    public function storageKeyFor(string $buildIdText, string $manifestPath): string
    {
        return $this->store->prefixFor(Uuid::toBytes($buildIdText)).'/'.$manifestPath;
    }

    /**
     * @param  string  $manifestId  raw 16 bytes
     * @return list<array{mount_path: string, build_id: string|null, is_primary: bool}>
     */
    private function loadMounts(string $manifestId): array
    {
        /*
         * Read across organisations, like the routing snapshot and for the same
         * reason: the reader has supplied a hostname and a path, and the tenant
         * was already decided by the host. Re-deriving it here would be a
         * second answer to a settled question, and two answers is how they
         * disagree.
         */
        $json = $this->context->acrossAllOrganisations(
            fn (): mixed => DB::table('project_version_manifests')
                ->where('id', $manifestId)
                ->value('mounts_json'),
        );

        if (! is_string($json)) {
            return [];
        }

        $decoded = json_decode($json, true);

        if (! is_array($decoded) || ! is_array($decoded['mounts'] ?? null)) {
            return [];
        }

        $mounts = [];

        foreach ($decoded['mounts'] as $mount) {
            if (! is_array($mount)) {
                continue;
            }

            $path = $mount['mount_path'] ?? null;
            $build = $mount['build_id'] ?? null;

            if (! is_string($path)) {
                continue;
            }

            $mounts[] = [
                'mount_path' => $path,
                'build_id' => is_string($build) ? $build : null,

                /*
                 * 🛑 Absent means NOT primary, never "probably". A manifest
                 * written before Phase 03 added the flag, or one whose JSON a
                 * restore truncated, must not make an arbitrary mount the one
                 * that emits downloads — §8.7.19's whole purpose is that the
                 * answer be unambiguous. A version with no primary mount has
                 * no downloads, which is a 404 the operator can act on.
                 */
                'is_primary' => ($mount['is_primary'] ?? false) === true,
            ];
        }

        return $mounts;
    }

    /**
     * @return array<string, array{sha256: string, bytes: int, content_type: string}>
     */
    private function loadFiles(string $buildIdText): array
    {
        $key = $this->store->keyFor(Uuid::toBytes($buildIdText), 'manifest').'/manifest.json';
        $bytes = $this->store->get($key);

        if ($bytes === null) {
            /*
             * A published manifest naming a build whose manifest.json is gone.
             * Returning an empty map makes every path a 404, which is the
             * correct answer — the build's bytes may have been swept (§8.8.9) —
             * and is far better than a 500: a reader gets "not found" rather
             * than an error page, and the operator sees the 404 rate rather
             * than an exception storm.
             */
            return [];
        }

        $manifest = FileManifest::decode($bytes);
        $files = [];

        foreach ($manifest->paths() as $path) {
            $entry = $manifest->get($path);

            if ($entry !== null) {
                $files[$path] = $entry;
            }
        }

        return $files;
    }
}
