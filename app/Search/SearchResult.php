<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * One result, with the URL §8.16.5 computes at query time.
 *
 * The shape the reader-facing surface needs, and deliberately the shape §8.15's
 * chrome runtime already expects — `{ title, href }` — plus the context a
 * result list wants. Phase 30 owns the endpoint that serialises it; this phase
 * owns the fact that there is something correct to serialise.
 */
final readonly class SearchResult
{
    /**
     * @param  string  $href  🛑 computed, never stored: the version's
     *                        `/{language}/{version}/` prefix, the matched
     *                        mount's path from the **manifest**, the document's
     *                        build-relative path and the anchor. Origin-relative,
     *                        because a documentation search answers on the
     *                        documentation host and a cross-origin absolute URL
     *                        is Phase 30's federation problem.
     * @param  string  $projectSlug  which project this URL belongs to — the
     *                               field that makes a reused build's two
     *                               results distinguishable
     */
    public function __construct(
        public string $title,
        public string $href,
        public string $projectSlug,
        public string $versionSlug,
        public string $language,
        public string $pageTitle,
        public string $headingPath,
        public string $excerpt,
        public float $score,
    ) {}

    /**
     * §8.15.8's payload shape, as the chrome runtime reads it.
     *
     * Kept here rather than in a controller because the runtime's contract is
     * `{ results: [{ title, href }] }` and a second place that assembled it
     * would be a second place to get it wrong. The extra keys are additive and
     * the runtime ignores what it does not know.
     *
     * @return array{title: string, href: string, project: string, version: string, page: string, section: string, excerpt: string}
     */
    public function toPayload(): array
    {
        return [
            'title' => $this->title,
            'href' => $this->href,
            'project' => $this->projectSlug,
            'version' => $this->versionSlug,
            'page' => $this->pageTitle,
            'section' => $this->headingPath,
            'excerpt' => $this->excerpt,
        ];
    }
}
