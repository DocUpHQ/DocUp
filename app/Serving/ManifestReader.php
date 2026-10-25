<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

use App\Artifacts\ArtifactIngestor;
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
        return $this->composition($manifestId)['mounts'];
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
     * 🛑 §8.7.16's per-version cross-reference map, by component key.
     *
     * One cached read of an immutable row, like {@see self::mounts()}. The
     * map is what `/_/x/{component_key}/{path}` resolves against and what
     * §8.7.17 hands to the addons payload, and both of those are on the
     * reader's path — so it must be answerable without touching a build.
     *
     * @param  string  $manifestId  raw 16 bytes
     * @return array<string, array{mount_path: string, build_id: string|null, objects_inv: bool}>
     */
    public function crossReferences(string $manifestId): array
    {
        /** @var array<string, array{mount_path: string, build_id: string|null, objects_inv: bool}> */
        return Cache::rememberForever(
            'manifest:xref:'.bin2hex($manifestId),
            fn (): array => $this->loadCrossReferences($manifestId),
        );
    }

    /**
     * 🛑 §8.7.15's generated redirects for shadowed paths.
     *
     * Keyed by the path relative to the version root, exactly as the
     * resolver's remainder spells it, so the lookup on the serving path is
     * an array read rather than a comparison.
     *
     * @param  string  $manifestId  raw 16 bytes
     * @return array<string, string>
     */
    public function shadowRedirects(string $manifestId): array
    {
        return $this->composition($manifestId)['shadow_redirects'];
    }

    /**
     * 🛑 Both halves of `mounts_json`, cached together.
     *
     * One cache read, not two. Every document request asks for the mounts,
     * and since Phase 14 it also asks for the shadow redirects — and the
     * two come out of the same immutable column, so caching them apart
     * would double the round trips on the hottest path in the product to
     * re-read one document. §9.2's budgets are per request, and "one more
     * small read" is how they go.
     *
     * @param  string  $manifestId  raw 16 bytes
     * @return array{mounts: list<array{mount_path: string, build_id: string|null, is_primary: bool}>, shadow_redirects: array<string, string>}
     */
    private function composition(string $manifestId): array
    {
        /** @var array{mounts: list<array{mount_path: string, build_id: string|null, is_primary: bool}>, shadow_redirects: array<string, string>} */
        return Cache::rememberForever(
            'manifest:composition:'.bin2hex($manifestId),
            fn (): array => [
                'mounts' => $this->loadMounts($manifestId),
                'shadow_redirects' => $this->loadShadowRedirects($manifestId),
            ],
        );
    }

    /**
     * §8.7.6's spliced navigation for one version, as stored.
     *
     * @param  string  $manifestId  raw 16 bytes
     * @return array<array-key, mixed>
     */
    public function navigation(string $manifestId): array
    {
        /** @var array<array-key, mixed> */
        return Cache::rememberForever(
            'manifest:navigation:'.bin2hex($manifestId),
            function () use ($manifestId): array {
                $nodes = $this->decodeColumn($manifestId, 'nav_json')['nodes'] ?? null;

                return is_array($nodes) ? $nodes : [];
            },
        );
    }

    /**
     * §8.7.6's stored nav fragment for one build, or null.
     *
     * 🛑 Read through {@see ArtifactStore}, never with a file function, for
     * the reason in the class note: the boundary is kept absolute even for
     * metadata DocUp itself wrote, because "it is only metadata" is how the
     * first documentation byte ends up in PHP.
     *
     * Cached forever like everything else here, and for the same reason: a
     * build's artifact is write-once (§8.8.1), so the bytes behind this key
     * can never change. Nothing on the serving path calls it — the fragment
     * is read at **publish**, to be spliced into a manifest — but it lives
     * here so the one place that knows how to read a build's stored
     * metadata stays one place.
     *
     * @param  string  $buildIdText  canonical UUID text
     */
    public function navFragment(string $buildIdText): ?string
    {
        /** @var string|null */
        return Cache::rememberForever(
            'manifest:nav:'.$buildIdText,
            fn (): ?string => $this->store->get(
                $this->storageKeyFor($buildIdText, ArtifactIngestor::NAV_LEAF),
            ),
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
     * One JSON column of one manifest row, decoded.
     *
     * Read across organisations for the reason {@see self::loadMounts()}
     * gives: the tenant was decided by the host, and re-deriving it here
     * would be a second answer to a settled question.
     *
     * @param  string  $manifestId  raw 16 bytes
     * @return array<array-key, mixed>
     */
    private function decodeColumn(string $manifestId, string $column): array
    {
        $json = $this->context->acrossAllOrganisations(
            fn (): mixed => DB::table('project_version_manifests')
                ->where('id', $manifestId)
                ->value($column),
        );

        if (! is_string($json)) {
            return [];
        }

        $decoded = json_decode($json, true);

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * @param  string  $manifestId  raw 16 bytes
     * @return array<string, array{mount_path: string, build_id: string|null, objects_inv: bool}>
     */
    private function loadCrossReferences(string $manifestId): array
    {
        $components = $this->decodeColumn($manifestId, 'xref_json')['components'] ?? null;

        if (! is_array($components)) {
            return [];
        }

        $map = [];

        foreach ($components as $key => $entry) {
            if (! is_string($key) || ! is_array($entry)) {
                continue;
            }

            $mountPath = $entry['mount_path'] ?? null;
            $buildId = $entry['build_id'] ?? null;

            if (! is_string($mountPath)) {
                continue;
            }

            $map[$key] = [
                'mount_path' => $mountPath,
                'build_id' => is_string($buildId) ? $buildId : null,

                /*
                 * Absent means NO inventory, never "probably". §8.7.16 wants
                 * `objects.inv` served "directly at a stable path with no
                 * redirect"; handing off a key that is not there would make
                 * a MkDocs component answer 500 to an intersphinx probe
                 * instead of 404.
                 */
                'objects_inv' => ($entry['objects_inv'] ?? false) === true,
            ];
        }

        return $map;
    }

    /**
     * @param  string  $manifestId  raw 16 bytes
     * @return array<string, string>
     */
    private function loadShadowRedirects(string $manifestId): array
    {
        $redirects = $this->decodeColumn($manifestId, 'mounts_json')['shadow_redirects'] ?? null;

        if (! is_array($redirects)) {
            return [];
        }

        $map = [];

        foreach ($redirects as $from => $to) {
            if (is_string($from) && is_string($to)) {
                $map[$from] = $to;
            }
        }

        return $map;
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
