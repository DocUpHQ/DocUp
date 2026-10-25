<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Serving;

use App\Auth\AccessLevel;
use App\Composition\CompositionSummary;
use App\Composition\MountPolicy;
use App\Models\Build;
use App\Models\ProjectVersion;
use App\Serving\RoutingSnapshotLoader;
use App\Support\Uuid;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 §8.7.21's reproducibility affordance: `GET /_/composition`.
 *
 * > "The system MUST expose the resolved composition of every published
 * > version — each component, resolved ref, commit, build id and build time
 * > — at `/_/composition` and through API v3. This is the reproducibility
 * > affordance and the auditor's answer to 'what was on this URL on
 * > 2026-03-04?'."
 *
 * 🛑 **Answered from the published manifest, not from the mount rows.** The
 * distinction is the whole point of the endpoint and is why it is not the
 * same question {@see CompositionSummary} answers for the
 * dashboard. A mount row says what the project is configured to serve
 * *now*; the manifest says what it *did* serve, and §10.4 makes a manifest
 * immutable so that answer cannot drift. An auditor asking about 4 March
 * needs the second one.
 *
 * 🛑 **Public versions only, and that is fail-closed rather than final.**
 * Reader authorisation is Phase 21's (§8.12), so there is no actor to ask
 * about yet. Listing a `members` version's components here would disclose
 * which repositories feed a private manual — §8.2.2's own concern — to
 * anyone who can reach the host. So the filter is the §12.3 lattice applied
 * to the version and its project, maximum of the two per §12.3, and
 * anything above `public` is simply absent. Phase 21 replaces the filter
 * with the real `EffectiveAccess` decision; until then absence is the safe
 * answer, and it is indistinguishable from a version that does not exist.
 */
final class CompositionController
{
    /**
     * A ceiling on how many versions one response describes.
     *
     * A project with four hundred versions would otherwise produce a
     * megabyte of JSON built from four hundred manifest reads, on an
     * endpoint nothing rate-limits yet. Newest first, so the bound truncates
     * the archive rather than the present.
     */
    private const MAX_VERSIONS = 100;

    public function __construct(private readonly RoutingSnapshotLoader $snapshots) {}

    public function __invoke(Request $request, string $docupHostLabel): JsonResponse
    {
        $snapshot = $this->snapshots->load((string) $request->getHost());

        if (! $snapshot->servable || $snapshot->mounts === []) {
            return $this->notFound();
        }

        $projectId = DB::table('domain_mounts')
            ->join('domains', 'domains.id', '=', 'domain_mounts.domain_id')
            ->where('domains.host', strtolower((string) $request->getHost()))
            ->where('domains.state', 'active')
            ->value('domain_mounts.project_id');

        if (! is_string($projectId)) {
            return $this->notFound();
        }

        /** @var list<ProjectVersion> $versions */
        $versions = array_values(
            ProjectVersion::withoutGlobalScopes()
                ->where('project_id', $projectId)
                ->where('published', true)
                ->whereNotNull('published_manifest_id')
                ->orderByDesc('created_at')
                ->limit(self::MAX_VERSIONS)
                ->get()
                ->all(),
        );

        $projectVisibility = DB::table('projects')->where('id', $projectId)->value('visibility');
        $projectLevel = is_string($projectVisibility)
            ? AccessLevel::from($projectVisibility)
            : AccessLevel::Members;

        $described = [];

        foreach ($versions as $version) {
            if (! $this->isPublic($version, $projectLevel)) {
                continue;
            }

            $described[] = $this->describe($version);
        }

        return response()->json(
            [
                'schema' => 'docup.composition/1',
                'versions' => $described,
            ],
            200,
            [
                // §7.3: nothing under `/_/` is publicly cacheable.
                'Cache-Control' => 'no-store',
                'X-Content-Type-Options' => 'nosniff',
            ],
        );
    }

    /**
     * §12.3's maximum of project and version visibility, as a public test.
     *
     * The same rule {@see MountPolicy::effectiveVisibility()}
     * applies, restated here against a raw project row because this route
     * has no ambient tenant and loading the project model would need one.
     */
    private function isPublic(ProjectVersion $version, AccessLevel $projectLevel): bool
    {
        return $projectLevel === AccessLevel::Public && $version->visibility === AccessLevel::Public;
    }

    /**
     * One version's resolved composition, from its immutable manifest.
     *
     * @return array<string, mixed>
     */
    private function describe(ProjectVersion $version): array
    {
        $manifestId = $version->getRawOriginal('published_manifest_id');

        $row = DB::table('project_version_manifests')
            ->where('id', $manifestId)
            ->first(['revision', 'mounts_json', 'created_at']);

        $mounts = [];

        if ($row !== null && is_string($row->mounts_json)) {
            $decoded = json_decode($row->mounts_json, true);
            $mounts = is_array($decoded) && is_array($decoded['mounts'] ?? null) ? $decoded['mounts'] : [];
        }

        $buildTimes = $this->buildTimesFor($mounts);
        $components = [];

        foreach ($mounts as $mount) {
            if (! is_array($mount)) {
                continue;
            }

            $buildId = is_string($mount['build_id'] ?? null) ? $mount['build_id'] : null;

            $components[] = [
                'component' => $mount['component_key'] ?? null,
                'mount_path' => $mount['mount_path'] ?? '',
                'is_primary' => ($mount['is_primary'] ?? false) === true,
                'selector' => $mount['selector_kind'] ?? null,
                'resolution' => $mount['resolution'] ?? null,
                'ref' => $mount['resolved_ref'] ?? null,
                'commit' => $mount['commit_sha'] ?? null,
                'build' => $buildId,
                'built_at' => $buildId === null ? null : ($buildTimes[$buildId] ?? null),
            ];
        }

        return [
            'version' => $version->slug,
            'language' => $version->language,
            'manifest_revision' => $row->revision ?? null,
            'published_at' => $row->created_at ?? null,
            'components' => $components,
        ];
    }

    /**
     * `finished_at` per build id, in one query.
     *
     * 🛑 Null-tolerant: §8.8.9's sweep may have removed a build row whose
     * manifest is still the published one, and §10.4 is explicit that a
     * manifest outlives the builds it names. An auditor reading a
     * five-year-old composition gets the commit SHA — which is the answer
     * that matters — and a null build time.
     *
     * @param  array<array-key, mixed>  $mounts
     * @return array<string, string>
     */
    private function buildTimesFor(array $mounts): array
    {
        $ids = [];

        foreach ($mounts as $mount) {
            if (is_array($mount) && is_string($mount['build_id'] ?? null)) {
                $bytes = Uuid::tryToBytes($mount['build_id']);

                if ($bytes !== null) {
                    $ids[] = $bytes;
                }
            }
        }

        if ($ids === []) {
            return [];
        }

        $times = [];

        foreach (Build::withoutGlobalScopes()->whereIn('id', $ids)->get() as $build) {
            $finished = $build->finished_at;

            if ($finished !== null) {
                $times[Uuid::toText($build->id)] = $finished->toIso8601String();
            }
        }

        return $times;
    }

    private function notFound(): JsonResponse
    {
        return response()->json(['error' => 'not_found'], 404, [
            'Cache-Control' => 'no-store',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }
}
