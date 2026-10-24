<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Config;

/**
 * §8.4.1's discovery order, and where it starts from.
 *
 * > "The system MUST accept a repository configuration file at a
 * > deterministic, logged discovery order: `.docup.yaml` → `.docup.yml` →
 * > `.readthedocs.yaml` → `.readthedocs.yml`. 🛑 Discovery MUST run
 * > **relative to `component_sources.source_path`**, not to the repository
 * > root, falling back to the root when `source_path` is empty."
 *
 * 🛑 **Rooting discovery at the repository would make the monorepo case
 * unexpressible**, and that case is the reason the component model exists:
 * "A monorepo contributing three components holds three configuration files
 * at three paths." One file at the root cannot say three different things.
 *
 * 🛑 **The order is the same list the fetcher walks**, and `ConfigDiscoveryTest`
 * asserts that `deploy/fetch-entrypoint.sh` contains exactly these names in
 * exactly this order. The fetcher is the thing that actually looks in the
 * working tree — it is the only container that has one — so a divergence
 * would mean the application validating a file the build never read.
 */
final class ConfigDiscovery
{
    /**
     * The candidates, in order. First match wins; the match is logged.
     *
     * DocUp's own names come first so that a repository migrating from Read
     * the Docs can adopt DocUp-specific configuration without deleting the
     * file its previous host still reads — which is the state every migration
     * passes through, and the only time both files exist at once.
     *
     * @var list<string>
     */
    public const CANDIDATES = [
        '.docup.yaml',
        '.docup.yml',
        '.readthedocs.yaml',
        '.readthedocs.yml',
    ];

    /**
     * The directory §8.4.1 searches, inside the checkout.
     *
     * @param  string  $checkoutRoot  where the fetcher put the working tree
     * @param  string  $sourcePath  `component_sources.source_path`; empty is the root
     */
    public static function directoryFor(string $checkoutRoot, string $sourcePath): string
    {
        $relative = trim($sourcePath, '/');

        return $relative === '' ? $checkoutRoot : $checkoutRoot.'/'.$relative;
    }

    /**
     * The first candidate that exists, or null.
     *
     * Returns the **name**, not the path: the name is what gets logged and
     * what §20.5 records as a compatibility shim ("Read after the DocUp
     * filenames; the match is logged"), and a caller that wanted the path can
     * join it to the directory it already passed in.
     */
    public static function findIn(string $directory): ?string
    {
        foreach (self::CANDIDATES as $candidate) {
            if (is_file($directory.'/'.$candidate)) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * Is this one of Read the Docs' names rather than one of ours?
     *
     * Used for the §20.5 log line, which exists so that an operator debugging
     * "why did my change not take effect" can see that the build read
     * `.readthedocs.yaml` while they were editing `.docup.yaml`.
     */
    public static function isCompatibilityName(string $filename): bool
    {
        return str_starts_with($filename, '.readthedocs.');
    }
}
