<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * §8.16.4's structured-index ingestion, for the two generators it names.
 *
 * > §8.16.4: "Where a generator already emits a structured index (Material for
 * > MkDocs `search_index.json`, Sphinx `-b json`), the system SHOULD ingest it
 * > rather than re-parsing HTML."
 *
 * ## Why it is worth preferring
 *
 * Not speed. The generator's index knows things §8.16.3's HTML extraction has
 * to **guess**: which part of the page is content, what the section titles are
 * before a theme decorated them, and which text the theme injected. Material's
 * index is written from the Markdown source, so it has no sidebar in it at all
 * — there is nothing to strip and therefore nothing to strip wrongly.
 *
 * ## 🛑 Why it is SHOULD and not MUST, and what that means here
 *
 * A structured index can be absent, truncated, from a different version of the
 * generator, or simply too large to hold in memory — and §9.2's indexer budget
 * is a MUST. So every route here is allowed to decline, and declining falls
 * back to §8.16.3's HTML extraction, which is bounded per file by construction.
 * A build whose structured index is unusable is still fully searchable; it is
 * searchable the other way, and {@see ExtractionReport} says which.
 *
 * 🛑 Both readers treat their input as **hostile**. A `search_index.json` is a
 * file inside a build artifact, which §14's threat model makes
 * attacker-controlled: a project can commit one by hand. So nothing is trusted
 * to be a string, a `location` cannot escape the build's path space, and the
 * whole file is refused above a declared size rather than decoded and hoped
 * about.
 */
final readonly class StructuredIndex
{
    /** Material for MkDocs' index, at its fixed location. */
    public const string MATERIAL_PATH = 'html/search/search_index.json';

    /** Sphinx's JSON builder writes this beside its `.fjson` pages. */
    public const string SPHINX_CONTEXT = 'globalcontext.json';

    /**
     * 🛑 The largest structured index decoded, in bytes.
     *
     * `json_decode` has no streaming mode, so the whole file becomes PHP arrays
     * at once and the peak is several times the file size. §9.2's budget is per
     * **indexer**, not per file, so one 40 MiB Material index on a 5,000-page
     * site would decide it — and that is the exact size such a site produces.
     *
     * Above the cap the build falls back to HTML extraction, which reads one
     * capped document at a time and is bounded whatever the site's size. So the
     * large sites that most need the budget are the ones that take the bounded
     * route, which is the right way round.
     */
    public const int MAX_INDEX_BYTES = 8 * 1024 * 1024;

    public function __construct(
        private MaterialIndexReader $material,
        private SphinxJsonReader $sphinx,
    ) {}

    /**
     * Read whichever structured index this build has, or null for none.
     *
     * Material first, because its index is one file at a fixed path and
     * therefore the cheapest thing to rule in or out. Sphinx's route needs a
     * scan of the manifest for `.fjson` pages, so it is asked second.
     *
     * @return array{0: ExtractedFrom, 1: list<Section>}|null
     */
    public function read(BuildFiles $files, SearchRanking $ranking): ?array
    {
        $sections = $this->material->read($files, $ranking);

        if ($sections !== null) {
            return [ExtractedFrom::Material, $sections];
        }

        $sections = $this->sphinx->read($files, $ranking);

        if ($sections !== null) {
            return [ExtractedFrom::Sphinx, $sections];
        }

        return null;
    }
}
