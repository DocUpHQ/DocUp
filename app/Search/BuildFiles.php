<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

use App\Artifacts\ArtifactStore;
use App\Serving\ManifestReader;

/**
 * One build's published files, as the indexer reads them.
 *
 * 🛑 Every byte comes through {@see ArtifactStore}, never a file function.
 * §8.8.2 makes the store the sole reader of an artifact and an architecture
 * test counts the call sites — the reason being the one §8.9.7 gives for the
 * serving path and which applies equally here: the artifacts disk may be S3, a
 * `file_get_contents` would work in development and fail in production, and the
 * failure would be a project whose search is silently empty.
 *
 * 🛑 **One file at a time, and nothing cached.** §9.2 budgets the indexer's
 * peak memory at "5,000 pages across 3 components", so this class deliberately
 * has no memoisation of file *contents*: the path list is small and is held,
 * the bytes are fetched, used and dropped. A content cache here would be the
 * single easiest way to blow the budget and the hardest to notice, because it
 * would make the tests faster.
 */
final readonly class BuildFiles
{
    /** The output contract's HTML root (§8.4.5). */
    public const string HTML_PREFIX = 'html/';

    /** @var array<string, array{sha256: string, bytes: int, content_type: string}> */
    private array $manifest;

    /**
     * @param  string  $buildIdText  canonical UUID text, as the manifest stores it
     */
    public function __construct(
        private ManifestReader $manifests,
        private ArtifactStore $store,
        private string $buildIdText,
    ) {
        $this->manifest = $this->manifests->files($this->buildIdText);
    }

    /**
     * Every published path in the build, as the file manifest spells them —
     * `html/guide/index.html`, `pdf/document.pdf`.
     *
     * @return list<string>
     */
    public function paths(): array
    {
        return array_keys($this->manifest);
    }

    /**
     * The HTML documents, **build-relative** — `guide/index.html`.
     *
     * 🛑 §8.16.5's key space, which is the whole reason this method exists
     * rather than callers trimming the prefix themselves: a document keyed
     * `html/guide/index.html` would compose into
     * `/en/latest/html/guide/index.html` at query time, and the bug would look
     * like a resolver fault rather than an indexing one.
     *
     * @return list<string>
     */
    public function documents(): array
    {
        $documents = [];

        foreach ($this->manifest as $path => $entry) {
            if (! str_starts_with($path, self::HTML_PREFIX)) {
                continue;
            }

            if (! self::isHtml($path, $entry['content_type'])) {
                continue;
            }

            $documents[] = substr($path, strlen(self::HTML_PREFIX));
        }

        /*
         * Sorted, so a build's documents are indexed in a stable order and
         * `position` means the same thing across two runs. The manifest's own
         * order is the archive's, which is whatever the generator's filesystem
         * handed the tar writer.
         */
        sort($documents);

        return $documents;
    }

    /** Bytes for one build-relative HTML path, or null. */
    public function document(string $buildRelativePath): ?string
    {
        return $this->raw(self::HTML_PREFIX.$buildRelativePath);
    }

    /** Bytes for one manifest path, or null. */
    public function raw(string $manifestPath): ?string
    {
        if (! isset($this->manifest[$manifestPath])) {
            return null;
        }

        return $this->store->get($this->manifests->storageKeyFor($this->buildIdText, $manifestPath));
    }

    /** The declared size of one manifest path, or null when it is absent. */
    public function bytes(string $manifestPath): ?int
    {
        return $this->manifest[$manifestPath]['bytes'] ?? null;
    }

    public function has(string $manifestPath): bool
    {
        return isset($this->manifest[$manifestPath]);
    }

    /** How many files the build published. */
    public function count(): int
    {
        return count($this->manifest);
    }

    /**
     * Whether a manifest entry is an HTML document.
     *
     * The declared content type first, because the ingestor set it from the
     * sniff and that is the authority (§8.4.18). The extension is the fallback
     * for a manifest written before a type was recorded — and both are needed,
     * because a generator that emits `.html` with `application/octet-stream` is
     * a real thing and so is a `.xhtml` served as XML.
     */
    private static function isHtml(string $path, string $contentType): bool
    {
        if (str_contains($contentType, 'html')) {
            return true;
        }

        $extension = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));

        return in_array($extension, ['html', 'htm', 'xhtml'], true);
    }
}
