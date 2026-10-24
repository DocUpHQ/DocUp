<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Versions;

use App\Models\ProjectVersion;
use App\Serving\ManifestReader;

/**
 * §8.6.11: does this page exist in that version?
 *
 * > "The system MUST answer **cross-version page existence**: when a reader
 * > switches version and the page is absent, the flyout MUST say so from the
 * > per-build file manifest rather than delivering a bare 404. The manifest
 * > makes a better answer here than Read the Docs can give."
 *
 * 🛑 **Answered from the manifest, never by fetching the file.** The
 * manifest is already loaded and cached for the version being served, and
 * the whole value of the answer is that it is available *before* the reader
 * clicks — a flyout that probed each version with a HEAD request would make
 * switching version cost one request per version in the list, on every page
 * load, to answer a question nobody has asked yet.
 *
 * 🛑 **A version with nothing published answers `false`, not "unknown".** The
 * three-state answer is tempting and wrong: a flyout showing "may or may not
 * exist" has told the reader nothing, and the honest statement about a
 * version with no manifest is that the page is not there — because it is
 * not.
 */
final readonly class PageExistence
{
    public function __construct(private ManifestReader $manifests) {}

    /**
     * Which of these versions hold this page.
     *
     * The key is the version's id as hex, because a caller rendering a
     * flyout has versions in hand and needs to look the answer up per row.
     *
     * @param  list<ProjectVersion>  $versions
     * @param  string  $manifestPath  e.g. `html/guide/index.html`
     * @return array<string, bool>
     */
    public function across(array $versions, string $manifestPath): array
    {
        $answers = [];

        foreach ($versions as $version) {
            $answers[bin2hex($version->id)] = $this->inVersion($version, $manifestPath);
        }

        return $answers;
    }

    /**
     * Does this version hold the page?
     *
     * @param  string  $manifestPath  the path as the file manifest stores it
     */
    public function inVersion(ProjectVersion $version, string $manifestPath): bool
    {
        foreach ($this->buildsOf($version) as $buildIdText) {
            if (array_key_exists($manifestPath, $this->manifests->files($buildIdText))) {
                return true;
            }
        }

        return false;
    }

    /**
     * The nearest existing page, for a reader switching version.
     *
     * 🛑 Walks UP the path rather than guessing sideways. A reader on
     * `/v2/guide/auth/tokens/` switching to `v1` is better served by
     * `/v1/guide/auth/` than by a 404 — and emphatically not by a search
     * result or a similarly-named page, which is the "helpful" behaviour
     * that sends somebody to documentation for a different feature without
     * telling them.
     *
     * Returns null when even the version's root is absent, which is the
     * honest answer for a version with nothing published.
     *
     * @param  string  $manifestPath  e.g. `html/guide/auth/tokens/index.html`
     */
    public function nearestIn(ProjectVersion $version, string $manifestPath): ?string
    {
        if ($this->inVersion($version, $manifestPath)) {
            return $manifestPath;
        }

        // `html/a/b/index.html` → `html/a/index.html` → `html/index.html`.
        $leaf = basename($manifestPath);
        $segments = explode('/', trim(dirname($manifestPath), '/'));

        while (count($segments) > 1) {
            array_pop($segments);
            $candidate = implode('/', $segments).'/'.$leaf;

            if ($this->inVersion($version, $candidate)) {
                return $candidate;
            }
        }

        $root = $segments[0].'/'.$leaf;

        return $this->inVersion($version, $root) ? $root : null;
    }

    /**
     * The builds behind a version's published manifest, as canonical text.
     *
     * 🛑 Plural, because §8.7's composition mounts several components into
     * one version and a page lives in exactly one of them. Answering from
     * the primary mount alone would report every composed page as absent in
     * every version — which is the shape of bug that looks like the feature
     * working badly rather than like a bug.
     *
     * @return list<string>
     */
    private function buildsOf(ProjectVersion $version): array
    {
        if ($version->published_manifest_id === null) {
            return [];
        }

        $builds = [];

        foreach ($this->manifests->mounts($version->published_manifest_id) as $mount) {
            if (is_string($mount['build_id']) && $mount['build_id'] !== '') {
                $builds[] = $mount['build_id'];
            }
        }

        return $builds;
    }
}
