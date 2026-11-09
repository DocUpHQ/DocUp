<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Addons;

use App\Artifacts\ArtifactIngestor;
use App\Artifacts\ArtifactStore;
use App\Artifacts\ChromeInjector;
use App\Artifacts\Publisher;
use App\Artifacts\TarArchiveWriter;
use App\Auth\OrganisationContext;
use App\Builds\BuildPipeline;
use App\Models\Build;
use App\Models\ProjectVersion;
use App\Support\Uuid;

/**
 * 🛑 §8.15.4's re-ingest job: "`builds.injector_version` MUST be stamped and a
 * re-ingest job MUST ship."
 *
 * ## Why one has to exist at all
 *
 * §8.15.1 puts two tags in every built HTML document **at ingest**, and §8.8.1
 * makes an artifact write-once. So when the tags change — a new loader path, a
 * third tag, a corrected escape — every artifact already in the store carries
 * the old generation and there is no way to edit it. §8.15.4's answer is the
 * stamp plus this: a deliberate re-ingest of a known set.
 *
 * ## 🛑 It re-publishes; it does not rewrite
 *
 * The stored tree is read back, tarred, and handed to the one
 * {@see Publisher::publishUpload()} — which runs the one
 * {@see ArtifactIngestor}, applies the current
 * {@see ChromeInjector}, writes a **new** build under a **new** id and flips the
 * version pointer through the same compare-and-swap an ordinary publish uses.
 *
 * Nothing is mutated in place, and that is the requirement rather than caution:
 * §8.8.1's write-once is what makes provenance mean anything (§8.5.24), and an
 * artifact whose bytes changed after publication would make every recorded
 * digest a lie. The old build stays exactly as it was and stops being pointed
 * at.
 *
 * 🛑 **And it needs no repository.** That is the point of re-ingesting rather
 * than rebuilding: §8.21.6's direct uploads have no source to rebuild from, a
 * repository may have moved or been deleted, and a rebuild would pick up
 * upstream changes nobody asked for — so "re-apply the current injector to the
 * bytes we have" is both cheaper and the only thing that is correct for every
 * build in the table.
 *
 * ## What is copied and what is not
 *
 * Only the format directories a build's own output contract produces. The
 * build's `manifest/` and `provenance/` are **excluded**, for the reason
 * {@see BuildPipeline} gives when it re-archives a cached fragment:
 * they are facts about that build and the ingest re-emits them for the new one.
 * Copying them would attribute the new build's output to the old build's plan.
 */
final readonly class ChromeReingest
{
    /**
     * Store prefixes that are a build's **own** metadata rather than its output.
     *
     * Named rather than derived from {@see ArtifactIngestor}'s
     * format list, so that a format added there is copied by default: the
     * failure mode of a missing format is a published version losing its PDF,
     * and the failure mode of copying metadata is caught by the ingest, which
     * refuses a directory it does not recognise.
     */
    private const array EXCLUDED_PREFIXES = ['manifest/', 'provenance/'];

    public function __construct(
        private ArtifactStore $store,
        private Publisher $publisher,
        private OrganisationContext $context,
        private PublishedBuild $published,
    ) {}

    /**
     * Every published build stamped with an injector older than the current one.
     *
     * 🛑 **Published only.** A superseded build is not re-ingested: no reader
     * can reach it, §20.3's reaper will collect it, and re-publishing it would
     * flip a pointer backwards. The query is therefore over the versions, not
     * over `builds`.
     *
     * @return list<ProjectVersion>
     */
    public function stale(): array
    {
        return $this->context->acrossAllOrganisations(function (): array {
            /** @var list<ProjectVersion> $versions */
            $versions = ProjectVersion::withoutGlobalScopes()
                ->whereNotNull('published_manifest_id')
                ->orderBy('created_at')
                ->get()
                ->all();

            return array_values(array_filter(
                $versions,
                fn (ProjectVersion $version): bool => $this->isStale($version),
            ));
        });
    }

    /**
     * Re-ingest one version's published build.
     *
     * @param  string  $workDirectory  where the intermediate archive is written
     * @return string|null the new build's id as text, or null when there was
     *                     nothing to copy
     */
    public function reingest(ProjectVersion $version, string $workDirectory): ?string
    {
        $build = $this->published->forVersion($version);

        if (! $build instanceof Build) {
            return null;
        }

        $buildIdText = Uuid::toText($build->id);
        $prefix = $this->store->prefixFor($buildIdText);
        $entries = [];

        foreach ($this->store->list($prefix) as $key) {
            $relative = ltrim(substr($key, strlen($prefix)), '/');

            if ($relative === '' || $this->isExcluded($relative)) {
                continue;
            }

            $contents = $this->store->get($key);

            if ($contents !== null) {
                $entries[$relative] = $contents;
            }
        }

        if ($entries === []) {
            /*
             * The prefix is empty. §20.3's reaper has already collected it, or
             * the store was emptied out of band — either way there are no bytes
             * to re-inject and inventing an empty publish would withdraw the
             * version's content.
             */
            return null;
        }

        ksort($entries);

        $archive = rtrim($workDirectory, '/\\').'/reingest-'.$buildIdText.'.tar';

        TarArchiveWriter::write($archive, $entries);

        try {
            return $this->context->withinOrganisation(
                (string) $version->organisation_id,
                function () use ($version, $archive): string {
                    $outcome = $this->publisher->publishUpload($version, $archive);

                    return $outcome->build === null ? '' : Uuid::toText($outcome->build->id);
                },
            );
        } finally {
            // The intermediate is never kept: the bytes are in the store twice
            // already and a stale tar in a work directory is a disclosure
            // waiting for somebody to serve the directory.
            @unlink($archive);
        }
    }

    /** Whether this version's published build predates the current injector. */
    private function isStale(ProjectVersion $version): bool
    {
        $build = $this->published->forVersion($version);

        if (! $build instanceof Build) {
            return false;
        }

        /*
         * Null means the build produced no HTML at all, which is never stale:
         * there is nothing in it carrying §8.15.1's tags. Phase 03 writes the
         * null for exactly this reason — "so the re-ingest job's query does not
         * return artifacts with nothing to do".
         */
        return $build->injector_version !== null
            && $build->injector_version < ChromeInjector::VERSION;
    }

    private function isExcluded(string $relative): bool
    {
        foreach (self::EXCLUDED_PREFIXES as $excluded) {
            if (str_starts_with($relative, $excluded)) {
                return true;
            }
        }

        return false;
    }
}
