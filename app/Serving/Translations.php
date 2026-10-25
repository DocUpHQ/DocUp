<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * Where a page exists across §8.6.12's translation group.
 *
 * 🛑 **One walk, two consumers, and that is why they are in one class.**
 * §8.11.6's `hreflang` set and §8.6.13's notification banner ask the same
 * question — *which languages hold this page?* — and answer it in opposite
 * directions: hreflang annotates the languages that have it, the banner names
 * them when the requested one does not. Two implementations of one question
 * would eventually annotate a page the banner had just called missing.
 *
 * 🛑 **Existence is read through the component mount, not from the path.**
 * A composed version (§8.7) serves `/reference/api.html` from a build whose
 * own manifest key is `html/api.html`, because the component mount's prefix is
 * the version's and not the build's. So the sibling's mounts are matched
 * exactly as the serving path matches the request's — anything else reports
 * every composed page as untranslated.
 */
final readonly class Translations
{
    public function __construct(
        private ManifestReader $manifests,
        private Resolver $resolver,
    ) {}

    /**
     * The languages of this page, on the project's canonical mount.
     *
     * `$within` is the path inside the version, as the resolver left it — so
     * `''` is the version root and the directory rules below match
     * {@see Resolver::resolveFile()}'s.
     *
     * Returns an empty list when the version is not part of a translation
     * group: §8.6.12 makes the group the only thing that says two versions are
     * the same documentation, and a project with one language has no
     * alternates to annotate rather than one alternate that is itself.
     *
     * @return list<array{language: string, path: string}>
     */
    public function pagesFor(
        SnapshotProject $project,
        SnapshotVersion $version,
        string $within,
        CanonicalLocation $location,
    ): array {
        $siblings = $project->translationsOf($version);

        if (count($siblings) < 2) {
            return [];
        }

        $mount = $location->mountFor($project);
        $scheme = $project->versioningScheme;
        $pages = [];

        foreach ($siblings as $sibling) {
            if (! $this->holdsPage($sibling, $within)) {
                continue;
            }

            $pages[] = [
                'language' => $sibling->language,
                'path' => VersionUrl::document($mount, $scheme, $sibling, $within),
            ];
        }

        return $pages;
    }

    /**
     * Every language this project publishes, with that language's default
     * landing page on the canonical mount.
     *
     * For §8.6.13's other case: the reader asked for a language the project
     * does not publish at all, so there is no page to look for and the honest
     * offer is the language's own root. A version root always exists for a
     * servable version — §8.4.5 makes `html/index.html` mandatory — so this
     * needs no existence check and costs no manifest read.
     *
     * @return list<array{language: string, href: string}>
     */
    public function languageRoots(SnapshotProject $project, CanonicalLocation $location): array
    {
        $mount = $location->mountFor($project);
        $scheme = $project->versioningScheme;
        $seen = [];
        $roots = [];

        foreach ($project->versions as $version) {
            if (! $version->isServable() || isset($seen[$version->language])) {
                continue;
            }

            $seen[$version->language] = true;

            $roots[] = [
                'language' => $version->language,
                'href' => $location->origin.VersionUrl::root($mount, $scheme, $version),
            ];
        }

        usort($roots, static fn (array $a, array $b): int => strcmp($a['language'], $b['language']));

        return $roots;
    }

    /**
     * Does this version serve this page?
     *
     * Answered from the file manifest, never by fetching the file — the
     * manifest is immutable and cached (§8.8.3), and the value of the answer
     * is that it is available before anybody asks for the bytes.
     */
    private function holdsPage(SnapshotVersion $version, string $within): bool
    {
        if ($version->publishedManifestId === null) {
            return false;
        }

        $match = $this->resolver->resolveMount(
            $this->manifests->mounts($version->publishedManifestId),
            $within,
        );

        if ($match === null || $match->buildId === null) {
            return false;
        }

        $files = $this->manifests->files($match->buildId);

        /*
         * The two forms {@see Resolver::resolveFile()} serves, and no others.
         * A path with no trailing slash that names a directory redirects
         * there rather than serving, and a redirect is not a page: offering
         * it as a translation would annotate one URL and deliver another.
         */
        $key = $match->within === '' || str_ends_with($match->within, '/')
            ? 'html/'.$match->within.'index.html'
            : 'html/'.$match->within;

        return array_key_exists($key, $files);
    }
}
