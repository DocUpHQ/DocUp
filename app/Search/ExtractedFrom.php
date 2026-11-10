<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * Which of §8.16.3's and §8.16.4's routes produced a document.
 *
 * > §8.16.4: "Where a generator already emits a structured index (Material for
 * > MkDocs `search_index.json`, Sphinx `-b json`), the system SHOULD ingest it
 * > rather than re-parsing HTML."
 *
 * Recorded per document because the two routes disagree in ways an operator
 * needs to see rather than discover. A generator's own index knows the section
 * titles its theme renders and the text its own stripping produced; HTML
 * extraction knows only what survived into the markup, and §8.16.3's
 * main-content detection is a heuristic over somebody else's template. When a
 * reader reports a missing result, the first useful question is which of the
 * two found the page.
 */
enum ExtractedFrom: string
{
    /** §8.16.3: DocUp parsed the built HTML. */
    case Html = 'html';

    /** §8.16.4: Material for MkDocs' `search/search_index.json`. */
    case Material = 'material';

    /** §8.16.4: Sphinx's `-b json` output. */
    case Sphinx = 'sphinx';

    public function label(): string
    {
        return match ($this) {
            self::Html => 'built HTML',
            self::Material => 'Material for MkDocs search index',
            self::Sphinx => 'Sphinx JSON build',
        };
    }
}
