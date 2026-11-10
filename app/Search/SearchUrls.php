<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

use App\Serving\ManifestReader;

/**
 * 🛑 §8.16.5's URL, computed at query time.
 *
 * > §8.16.5: "Search documents MUST be keyed to `build_id` and a path
 * > **relative to the build**, never to an absolute URL, with result URLs
 * > computed at query time from the manifest's mount table. A reused build is
 * > then indexed **once** and is searchable from every project that mounts it."
 *
 * This class is the second half of that sentence. A hit knows its build and its
 * build-relative path; a {@see ScopeFact} knows which project version mounts
 * that build, at what path, in which language. Putting the two together gives a
 * URL — and because one hit can have several facts, exit criterion 5's reused
 * build produces one result **per mounting project**, each with its own correct
 * URL, out of one document.
 *
 * ## 🛑 The mount path comes from the manifest, every time
 *
 * Not from a column on the scope row. §8.8.3's manifest is the authority for
 * what a version publishes and it is immutable, so `ManifestReader` caches it
 * for ever and the lookup is an array read. Copying the mount path onto a scope
 * row would have been one less join and a second source for one fact: a version
 * that republished with a component moved from `/` to `/api/` would then serve
 * search results pointing at the old path, and the link would 404 while the
 * page existed.
 *
 * ## Why the URL is origin-relative
 *
 * A documentation search answers on the documentation host, so `/en/latest/…`
 * is complete and correct, and it is what §8.15's chrome runtime can follow
 * without knowing anything about domains. §8.16.10's cross-project search
 * within a collection needs absolute URLs across hosts and is Phase 30's
 * deliverable — this class would gain the origin from the collection's routing,
 * not from the request, and that is a design decision that phase should make
 * with the federation in front of it.
 */
final readonly class SearchUrls
{
    public function __construct(private ManifestReader $manifests) {}

    /**
     * Turn engine hits into results, one per (hit, fact) pair.
     *
     * 🛑 Ordered by the engine's ordering, not re-sorted. The engines express
     * relevance differently — an unbounded IDF sum on MySQL, a ranking-rule
     * ordering on Meilisearch — so a sort here would have to invent a
     * comparable number and would silently disagree with one of them. What the
     * shared contract suite asserts is that each engine's **order** is correct;
     * preserving it is this method's whole contribution to that.
     *
     * A hit with more than one fact keeps its neighbours: the two results for
     * one reused section are adjacent, which is what a reader expects from
     * "this page exists in two places".
     *
     * @param  list<DocumentHit>  $hits
     * @param  int  $limit  applied **after** expansion, because a reused
     *                      build's two URLs are two results and a limit of ten
     *                      must mean ten results rather than ten documents
     * @return list<SearchResult>
     */
    public function resultsFor(array $hits, AuthorisedScope $scope, int $limit): array
    {
        $results = [];

        foreach ($hits as $hit) {
            foreach ($scope->factsFor($hit->buildId, $hit->buildGeneration) as $fact) {
                $href = $this->hrefFor($hit, $fact);

                if ($href === null) {
                    continue;
                }

                $results[] = new SearchResult(
                    title: $hit->title !== '' ? $hit->title : $hit->pageTitle,
                    href: $href,
                    projectSlug: $fact->projectSlug,
                    versionSlug: $fact->versionSlug,
                    language: $fact->language,
                    pageTitle: $hit->pageTitle,
                    headingPath: $hit->headingPath,
                    excerpt: $this->excerpt($hit->content),
                    score: $hit->score,
                );

                if (count($results) >= $limit) {
                    return $results;
                }
            }
        }

        return $results;
    }

    /**
     * The URL for one hit under one mount context, or null.
     *
     * Null when the manifest does not place this build — a version that
     * republished without the component, say. Dropping the result is the only
     * honest option: the document exists and is no longer reachable at any URL
     * under this version, so offering a link would offer a 404.
     */
    public function hrefFor(DocumentHit $hit, ScopeFact $fact): ?string
    {
        $mountPath = $this->mountPathFor($fact, $hit->buildId);

        if ($mountPath === null) {
            return null;
        }

        /*
         * §7.3's grammar: `/{language}/{version}/{path}`. The mount path sits
         * between the version and the document's own path, which is what a
         * composed version is — §8.7's components mounted under one version.
         */
        $segments = trim($fact->language, '/').'/'.trim($fact->versionSlug, '/');
        $mountPath = trim($mountPath, '/');

        if ($mountPath !== '') {
            $segments .= '/'.$mountPath;
        }

        $path = ltrim($hit->path, '/');

        /*
         * 🛑 §8.9.7's directory form, in reverse. The stored path is a **file**
         * — `guide/index.html` — and the URL a reader should land on is the
         * directory, `guide/`, because that is the canonical form the resolver
         * 302s to and the form the generator's own links use. Emitting
         * `guide/index.html` would work and would then be redirected, costing
         * the reader a round trip and making every search result's URL differ
         * from the one in their address bar afterwards.
         */
        if (str_ends_with($path, '/index.html')) {
            $path = substr($path, 0, -strlen('index.html'));
        } elseif ($path === 'index.html') {
            $path = '';
        }

        $href = '/'.$segments.'/'.$path;

        /*
         * 🛑 Percent-encode each segment, and the anchor, without touching the
         * separators. A heading id can legitimately hold a character that must
         * be encoded in a URL — a CJK heading's own id, an em dash, a space in
         * a hand-written `id` — and emitting it raw produces a link browsers
         * normalise inconsistently. `rawurlencode` per segment is the form that
         * survives both.
         */
        $href = implode('/', array_map(
            static fn (string $segment): string => rawurlencode($segment),
            explode('/', $href),
        ));

        if ($hit->anchor !== null && $hit->anchor !== '') {
            $href .= '#'.rawurlencode($hit->anchor);
        }

        return $href;
    }

    /**
     * Where this build is mounted in the version's published manifest.
     *
     * 🛑 The **manifest's** mount table, per §8.16.5. The first mount naming the
     * build wins: a component mounted twice in one version is two paths for one
     * build, and `AuthorisedScope::documentKeys()` has already deduplicated the
     * pair — so offering both paths would mean every result from that component
     * appearing twice, which is noise rather than information. The deterministic
     * first is the mount the manifest lists first, which is the order
     * `Publisher` wrote.
     */
    private function mountPathFor(ScopeFact $fact, string $buildId): ?string
    {
        if ($fact->manifestId === null) {
            return null;
        }

        foreach ($this->manifests->mounts($fact->manifestId) as $mount) {
            if ($mount['build_id'] === $buildId) {
                return $mount['mount_path'];
            }
        }

        return null;
    }

    /**
     * A short excerpt of the section's text.
     *
     * 🛑 The **beginning** of the section, not the matched term's
     * neighbourhood. §8.16.10 puts "result highlighting" in Phase 30, and a
     * server-side snippet around the match is half of highlighting: it needs
     * the term positions, it differs per engine, and getting it wrong is how a
     * result list shows a reader the same twenty words for every hit. The
     * section's opening sentences are useful on their own and are the same on
     * both engines, which is what §8.16.12's "identical suite" needs.
     */
    private function excerpt(string $content): string
    {
        return mb_substr($content, 0, 200);
    }
}
