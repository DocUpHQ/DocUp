<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

/**
 * 🛑 §8.7.15's prefix test: which mount paths hide which.
 *
 * > "A new mount path that is a prefix of, or prefixed by, an existing mount
 * > path in the same project version MUST be **refused by default**; on
 * > explicit audited override the system MUST auto-generate redirect rows
 * > for every shadowed path identified from the affected builds' file
 * > manifests."
 *
 * 🛑 **The root mount is excluded, deliberately and with a reason.** §8.7.3
 * requires exactly one primary mount at `mount_path=''`, and `''` is a
 * prefix of every path there is — so applying the rule literally would make
 * a second mount impossible and §8.7.15 would forbid the feature §8.7 is
 * about. The root is not a competitor for a prefix: §8.7.12 resolves by
 * **longest** prefix, which makes the root the designed fallback and every
 * deeper mount a deliberate narrowing of it.
 *
 * What the root loses to a deeper mount is real, and it is not ignored — it
 * is caught one step later by {@see CompositionCollisions}, which compares
 * the actual file manifests and can say *which paths* disappeared. That is
 * strictly better than a structural refusal here could manage: a root mount
 * with no files under `guide/` loses nothing at all when `guide` is mounted,
 * and refusing it would be refusing a composition that has no problem.
 *
 * Comparison is on **segment boundaries**, the same rule §7.3 gives the
 * resolver. `guide` does not shadow `guidelines`, because no path under
 * `guidelines/` is ever matched by a mount at `guide`.
 */
final readonly class MountShadowing
{
    /**
     * Whether one mount path hides part of another's URL space.
     *
     * Symmetric: it does not matter which arrived first, because the
     * resolver's longest-prefix match does not care either. The caller
     * decides which of the two is "new".
     */
    public static function conflict(string $a, string $b): bool
    {
        if ($a === '' || $b === '') {
            // The root, which §8.7.3 mandates and §8.7.12 makes the fallback.
            return false;
        }

        if ($a === $b) {
            // Not shadowing — this is `UNIQUE (project_version_id,
            // mount_path_hash)`, and reporting it as a shadow would give one
            // refusal two identifiers.
            return false;
        }

        return self::prefixes($a, $b) || self::prefixes($b, $a);
    }

    /** Whether `$prefix` contains `$path` on a segment boundary. */
    public static function prefixes(string $prefix, string $path): bool
    {
        if ($prefix === '') {
            return true;
        }

        return str_starts_with($path, $prefix.'/');
    }

    /**
     * The part of `$path` below `$prefix`, or null when it is not below it.
     *
     * Used to turn a shadowed file path back into the relative path the
     * deeper mount would have served, which is what a redirect target needs.
     */
    public static function below(string $prefix, string $path): ?string
    {
        if ($prefix === '') {
            return $path;
        }

        if (! self::prefixes($prefix, $path)) {
            return null;
        }

        return substr($path, strlen($prefix) + 1);
    }
}
