<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Addons;

use App\Artifacts\ChromeInjector;
use App\Artifacts\InjectionCoverage;
use App\Artifacts\InjectionOutcome;
use App\Auth\OrganisationContext;
use App\Models\Build;
use App\Models\Project;
use App\Models\ProjectVersion;

/**
 * 🛑 §8.15.3's build warning and §8.15.4's per-project warning, surfaced.
 *
 * > §8.15.3: "Per-build injection coverage MUST be recorded and reported as a
 * > build warning with samples."
 *
 * > §8.15.4: "An artifact that cannot be injected MUST fall back to
 * > `chrome_mode: api_only` for that build, surfaced as a **per-project
 * > warning naming the affected files**."
 *
 * Phase 03 recorded the coverage onto `builds.chrome_coverage` and Phase 28
 * reports it. The record and the report are different jobs and were deliberately
 * built in different phases: §8.15.3's record is a property of ingest, and the
 * warning is a thing somebody has to be able to read.
 *
 * ## 🛑 Two warnings, two scopes, and they are not the same set
 *
 * A **build** warning is about one artifact and names the files in it that could
 * not be injected. A **project** warning is about what readers are getting right
 * now: it looks only at the builds behind each version's **published** manifest,
 * because a failed experiment from three weeks ago is not something to warn an
 * operator about today.
 *
 * 🛑 And navigational stubs are excluded from both, which is
 * {@see InjectionOutcome::raisesWarning()}'s whole purpose and ADR 0002's
 * finding: "every Antora site warns on every build forever and operators learn
 * to ignore injection warnings". The stubs stay in the record
 * ({@see InjectionCoverage::toArray()}) and out of the warning.
 */
final readonly class ChromeHealth
{
    public function __construct(
        private OrganisationContext $context,
        private PublishedBuild $published,
    ) {}

    /**
     * §8.15.3's warning for one build, or null when there is nothing to say.
     *
     * @return array{
     *     injector_version: int|null,
     *     current_injector_version: int,
     *     stale: bool,
     *     mode_applied: string|null,
     *     documents: int,
     *     injected: int,
     *     percentage: float,
     *     warning: array{files: list<string>, outcomes: array<string, int>}|null
     * }
     */
    public function forBuild(Build $build): array
    {
        /** @var array<string, mixed> $coverage */
        $coverage = is_array($build->chrome_coverage) ? $build->chrome_coverage : [];

        $documents = self::intOf($coverage, 'documents');
        $injected = self::intOf($coverage, 'injected');
        $version = $build->injector_version;

        return [
            'injector_version' => $version,
            'current_injector_version' => ChromeInjector::VERSION,

            /*
             * 🛑 §8.15.4: "`builds.injector_version` MUST be stamped and a
             * re-ingest job MUST ship." This is the flag the job acts on, and
             * reporting it is what makes the job's existence meaningful to an
             * operator: an artifact stamped with an older injector carries an
             * older generation of §8.15.1's two tags, and artifacts are
             * immutable (§8.8.1), so the only remedy is a deliberate re-ingest.
             *
             * A build with no HTML at all is stamped null and is never stale —
             * there is nothing in it to re-inject.
             */
            'stale' => $version !== null && $version < ChromeInjector::VERSION,

            'mode_applied' => $build->chrome_mode_applied,
            'documents' => $documents,
            'injected' => $injected,
            'percentage' => $documents === 0 ? 100.0 : round(($injected / $documents) * 100, 2),
            'warning' => $this->warningFrom($coverage),
        ];
    }

    /**
     * 🛑 §8.15.4's per-project warning, over what is **published**.
     *
     * @return array{
     *     mode: string,
     *     mode_applied: string,
     *     stale_builds: int,
     *     warning: array{versions: array<string, array{files: list<string>, outcomes: array<string, int>}>}|null
     * }
     */
    public function forProject(Project $project): array
    {
        return $this->context->withinOrganisation((string) $project->organisation_id, function () use ($project): array {
            /** @var list<ProjectVersion> $versions */
            $versions = ProjectVersion::query()
                ->where('project_id', $project->id)
                ->whereNotNull('published_manifest_id')
                ->get()
                ->all();

            $byVersion = [];
            $stale = 0;
            $applied = (string) $project->chrome_mode;

            foreach ($versions as $version) {
                $build = $this->published->forVersion($version);

                if (! $build instanceof Build) {
                    continue;
                }

                $report = $this->forBuild($build);

                if ($report['stale']) {
                    $stale++;
                }

                /*
                 * 🛑 The APPLIED mode is the worst case across published
                 * versions, not the project's column. §8.15.4 falls back per
                 * build, and a project where one version fell back to
                 * `api_only` is a project whose readers see chrome on some
                 * versions and not others — which is exactly the thing an
                 * operator needs told, and exactly what a per-build view
                 * scattered across versions does not say.
                 */
                if ($project->chrome_mode === 'injected' && $report['mode_applied'] === 'api_only') {
                    $applied = 'api_only';
                }

                if ($report['warning'] !== null) {
                    $byVersion[$version->language.'/'.$version->slug] = $report['warning'];
                }
            }

            return [
                'mode' => (string) $project->chrome_mode,
                'mode_applied' => $applied,
                'stale_builds' => $stale,
                'warning' => $byVersion === [] ? null : ['versions' => $byVersion],
            ];
        });
    }

    /**
     * The warning half of a stored coverage record.
     *
     * 🛑 Reads `warning_samples` and never `stub_samples`. The two sets are
     * separate in the stored record for this reason, and a reader of the record
     * that merged them would undo ADR 0002's finding at the presentation layer
     * rather than at the recording layer — which is harder to notice and just as
     * damaging.
     *
     * @param  array<string, mixed>  $coverage
     * @return array{files: list<string>, outcomes: array<string, int>}|null
     */
    private function warningFrom(array $coverage): ?array
    {
        $samples = $coverage['warning_samples'] ?? null;

        if (! is_array($samples) || $samples === []) {
            return null;
        }

        $files = [];

        foreach ($samples as $sample) {
            if (is_string($sample)) {
                $files[] = $sample;
            }
        }

        $outcomes = [];

        if (is_array($coverage['outcomes'] ?? null)) {
            foreach ($coverage['outcomes'] as $name => $count) {
                if (is_string($name) && is_numeric($count)) {
                    $outcomes[$name] = (int) $count;
                }
            }
        }

        return $files === [] ? null : ['files' => $files, 'outcomes' => $outcomes];
    }

    /** @param array<string, mixed> $coverage */
    private static function intOf(array $coverage, string $key): int
    {
        $value = $coverage[$key] ?? 0;

        return is_numeric($value) ? (int) $value : 0;
    }
}
