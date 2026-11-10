<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Addons\ChromeHealth;
use App\Addons\ChromeReingest;
use App\Artifacts\ChromeInjector;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Support\Uuid;
use Illuminate\Console\Command;

/**
 * `docup:reingest-chrome` — §8.15.4's re-ingest job.
 *
 * > "`builds.injector_version` MUST be stamped and a re-ingest job MUST ship."
 *
 * {@see ChromeReingest} is the work and this is how an operator reaches it.
 *
 * ## 🛑 `--dry-run` is the default posture, and the reason is the blast radius
 *
 * A re-ingest publishes. Every version it touches gets a new build, a new
 * manifest and a pointer flip — which means a new strong ETag on every
 * document, so every reader's cache and every CDN entry for that project is
 * invalidated at once. On an installation with a thousand versions that is a
 * cache stampede somebody should choose deliberately, at a time they choose.
 *
 * So the command lists what it would do unless `--publish` is passed, and
 * `--limit` is there to make "do a hundred, watch the graphs, do a hundred
 * more" the easy thing. §15 is the operations chapter and this is an
 * operations tool: the dangerous version must not be the one that is shorter
 * to type.
 *
 * ## 🛑 Nothing here is scheduled
 *
 * An upgrade that changes {@see ChromeInjector::VERSION} does **not** trigger
 * this. §8.8.1 makes artifacts write-once and §8.15.4 calls for "a deliberate
 * re-ingest of a known set" — a job that ran itself on upgrade would republish
 * every version on the installation during a deployment window, which is the
 * worst possible moment for it. The stamp is reported on the build and project
 * API endpoints ({@see ChromeHealth}) so an operator can see what
 * is stale and decide.
 */
final class ReingestChromeCommand extends Command
{
    protected $signature = 'docup:reingest-chrome
        {--publish : Actually re-ingest. Without this the command only reports}
        {--project= : Limit to one project, by slug or UUID}
        {--limit=0 : Stop after this many versions (0 means no limit)}';

    protected $description = 'Re-apply §8.15.1’s chrome tags to artifacts stamped with an older injector (§8.15.4)';

    public function handle(ChromeReingest $reingest): int
    {
        $stale = $reingest->stale();
        $filter = $this->option('project');

        if (is_string($filter) && $filter !== '') {
            $stale = $this->onlyProject($stale, $filter);

            if ($stale === null) {
                $this->components->error('No project matches '.$filter.'.');

                return self::FAILURE;
            }
        }

        $limit = (int) $this->option('limit');

        if ($limit > 0) {
            $stale = array_slice($stale, 0, $limit);
        }

        if ($stale === []) {
            $this->components->info(
                'Every published artifact carries injector version '.ChromeInjector::VERSION.'. Nothing to do.',
            );

            return self::SUCCESS;
        }

        $this->components->twoColumnDetail(
            'Current injector version',
            (string) ChromeInjector::VERSION,
        );
        $this->components->twoColumnDetail('Versions to re-ingest', (string) count($stale));

        if ($this->option('publish') !== true) {
            foreach ($stale as $version) {
                $this->components->twoColumnDetail(
                    $this->describe($version),
                    'would re-ingest',
                );
            }

            $this->components->warn('Dry run. Pass --publish to re-ingest, and read the note in the command about why.');

            return self::SUCCESS;
        }

        /*
         * 🛑 The work directory is the framework's own temporary path, not the
         * artifact store's. The intermediate tar is a complete copy of a
         * published tree, and putting it inside the store would make it
         * reachable by a path the resolver might one day walk — see §8.9.6's
         * argument about what a URL may name.
         */
        $work = sys_get_temp_dir();
        $done = 0;
        $failed = 0;

        foreach ($stale as $version) {
            try {
                $newBuild = $reingest->reingest($version, $work);
            } catch (\Throwable $exception) {
                /*
                 * 🛑 One version's failure does not stop the run, and it is
                 * reported rather than swallowed. The same argument §8.7.16
                 * makes about cross-references: "one repository's typo must not
                 * break another repository's build". A quota refusal or a
                 * missing prefix is about one version.
                 */
                $failed++;
                $this->components->twoColumnDetail(
                    $this->describe($version),
                    '<fg=red>failed: '.$exception->getMessage().'</>',
                );

                continue;
            }

            if ($newBuild === null) {
                $this->components->twoColumnDetail(
                    $this->describe($version),
                    '<fg=yellow>skipped: no stored bytes</>',
                );

                continue;
            }

            $done++;
            $this->components->twoColumnDetail($this->describe($version), 'published '.$newBuild);
        }

        $this->components->info('Re-ingested '.$done.' version(s); '.$failed.' failed.');

        return $failed === 0 ? self::SUCCESS : self::FAILURE;
    }

    /**
     * @param  list<ProjectVersion>  $stale
     * @return list<ProjectVersion>|null
     */
    private function onlyProject(array $stale, string $filter): ?array
    {
        $project = Project::withoutGlobalScopes()
            ->where('slug', $filter)
            ->orWhere('id', Uuid::tryToBytes($filter) ?? str_repeat("\xff", 16))
            ->first();

        if (! $project instanceof Project) {
            return null;
        }

        return array_values(array_filter(
            $stale,
            static fn (ProjectVersion $version): bool => $version->project_id === $project->id,
        ));
    }

    private function describe(ProjectVersion $version): string
    {
        $project = Project::withoutGlobalScopes()->whereKey($version->project_id)->first();

        return ($project instanceof Project ? $project->slug : '?')
            .' '.$version->language.'/'.$version->slug;
    }
}
