<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

use App\Builds\PathGlob;
use App\Models\ComponentSource;
use App\Webhooks\PushEvent;

/**
 * §17 Phase 13's "path-filter rebuild gating": did this push touch this
 * component's subtree?
 *
 * 🛑 The question is asked of the **source**, not of the project. A
 * monorepo's three components each own a subtree, and "did my subtree
 * change?" is a fact about `component_sources.source_path` — which is what
 * lets one push rebuild exactly the components it changed however many
 * projects consume them. Phase 11's `BuildSkipRule` asks a different and
 * complementary question, "does this project want to build at all?", and
 * both run.
 *
 * 🛑 §8.5.4's truncation rule applies here with the same force it applies
 * there: "Where a provider may truncate its changed-file arrays, the system
 * MUST treat the payload as 'everything changed'." A source whose subtree
 * cannot be shown to be clean is dirty. Getting this wrong in the other
 * direction means a component silently stops rebuilding, and §18.15 already
 * records that the whole path-filter idea is an assumption with a
 * pre-decided consequence: "Default to rebuilding every component in a
 * repository on push, with path filters an explicit opt-in optimisation."
 *
 * So the default here IS "rebuild", and a filter only ever makes a build
 * *not* happen when the evidence is complete.
 */
final readonly class SourceDirtiness
{
    /**
     * Whether this push requires this source to be rebuilt.
     *
     * Four ways to be dirty, and only one way to be clean:
     *
     *   1. There is no push to reason about — a manual build, a schedule,
     *      an `ls-remote` poll. Dirty.
     *   2. §8.5.4 detected truncation, or the provider sent no file list.
     *      Dirty, per the requirement's "treat the payload as everything
     *      changed".
     *   3. A changed path matches this source's filters. Dirty, obviously.
     *   4. The source is rooted at the repository root with no explicit
     *      filters, so every path is inside it. Dirty.
     *
     * Clean is the single remaining case: a complete file list, none of
     * which is inside a subtree this source genuinely narrows.
     */
    public function isDirty(ComponentSource $source, ?PushEvent $event): bool
    {
        if (! $event instanceof PushEvent) {
            return true;
        }

        if (! $event->changedPathsAreTrustworthy()) {
            return true;
        }

        $globs = $this->globsFor($source);

        if ($globs === []) {
            /*
             * A source at the repository root with no filters narrows
             * nothing, so every push touches it. Returning true here rather
             * than matching `**` is the same answer with one fewer regex,
             * and it says the reason out loud.
             */
            return true;
        }

        return PathGlob::anyMatches($globs, $event->changedPaths);
    }

    /**
     * The globs that decide dirtiness for one source.
     *
     * 🛑 Explicit `path_filters` win; otherwise the filter is derived from
     * `source_path`. The derivation is what makes this useful without
     * configuration: a component rooted at `docs/api` is dirty when
     * `docs/api/**` changes, which is what every operator would have typed.
     *
     * An empty list means "no narrowing", which {@see isDirty()} reads as
     * always dirty — never as "matches nothing".
     *
     * @return list<string>
     */
    public function globsFor(ComponentSource $source): array
    {
        $filters = $source->path_filters;

        if (is_array($filters) && $filters !== []) {
            $globs = [];

            foreach ($filters as $filter) {
                if (is_string($filter) && $filter !== '') {
                    $globs[] = $filter;
                }
            }

            return $globs;
        }

        $path = trim($source->source_path, '/');

        return $path === '' ? [] : [$path.'/**'];
    }
}
