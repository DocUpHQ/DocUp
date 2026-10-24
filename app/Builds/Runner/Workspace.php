<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Runner;

use App\Builds\BuildConfig;
use App\Builds\RunSpecification;

/**
 * The build workspace on disk, and §8.5.18's disk limit measured against it.
 *
 * 🛑 **Why the runner can see a build's files at all.** The workspace root
 * is bind-mounted into the runner at the same path it has on the host, so
 * the directory the daemon mounts into a build container is literally the
 * directory this process can `stat`. §8.5.18 requires an **enforced** disk
 * limit, explicitly contrasted with "Read the Docs' unenforced soft
 * limits", and the two ways to hand the kernel that job were both measured
 * and both refused in Phase 07 — `--storage-opt size=` needs
 * overlay-on-xfs with pquota, and a `type=tmpfs` volume is remounted empty
 * for every container, which loses the checkout between stages.
 *
 * So the limit is enforced by measurement, from a process outside the
 * sandbox, on a cadence short enough that the overshoot is bounded by
 * whatever a build can write in one tick.
 */
final class Workspace
{
    /**
     * The host path for a workspace name.
     *
     * 🛑 The name is a {@see RunSpecification} `volume`, which
     * that class validates against `[a-z0-9][a-z0-9_.-]{0,62}` — no
     * slashes, no `..`, no leading dot. That validation is what makes
     * appending it to a root safe, so it is restated here rather than
     * assumed: a path assembled from an unchecked name is a traversal, and
     * this one is handed to the container runtime as a bind source.
     */
    public static function pathFor(string $volume): string
    {
        if (preg_match('/^[a-z0-9][a-z0-9_.-]{0,62}$/', $volume) !== 1) {
            throw new \InvalidArgumentException('not a workspace name: '.substr($volume, 0, 64));
        }

        return rtrim(BuildConfig::string('workspace_root', '/var/lib/docup/workspaces'), '/').'/'.$volume;
    }

    /** True when the runner can see the workspace root at all. */
    public static function rootIsVisible(): bool
    {
        return is_dir(BuildConfig::string('workspace_root', '/var/lib/docup/workspaces'));
    }

    /**
     * Bytes used by a workspace, stopping as soon as `$ceiling` is passed.
     *
     * 🛑 **The early exit is the design, not an optimisation.** This runs
     * in the loop that reads a container's output, so its cost has to be
     * proportional to the question being asked — and the question is "is
     * this build over its limit", not "exactly how large is it". A build
     * writing a 10 GB file is detected after one `stat`; a build with
     * fifty thousand small files under the cap is the slow case, and it is
     * the case where there is no urgency.
     *
     * Symlinks are not followed. A build that symlinks `/usr` into its
     * workspace has not used any disk, and following it would both
     * mis-measure and walk out of the tree being measured.
     */
    public static function bytesUsed(string $path, int $ceiling = PHP_INT_MAX): int
    {
        if (! is_dir($path)) {
            return 0;
        }

        $total = 0;
        $stack = [$path];

        while ($stack !== []) {
            $directory = array_pop($stack);
            $handle = @opendir($directory);

            if ($handle === false) {
                continue;
            }

            while (($entry = readdir($handle)) !== false) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }

                $full = $directory.'/'.$entry;

                if (is_link($full)) {
                    continue;
                }

                if (is_dir($full)) {
                    $stack[] = $full;

                    continue;
                }

                $total += (int) @filesize($full);

                if ($total > $ceiling) {
                    closedir($handle);

                    return $total;
                }
            }

            closedir($handle);
        }

        return $total;
    }

    /**
     * Remove a workspace.
     *
     * 🛑 Refuses to walk out of the configured root. The caller passes a
     * path this class produced, so the check should never fire — which is
     * exactly why it is here: a recursive delete that trusts its argument
     * is one bad refactor away from removing something else.
     */
    public static function remove(string $path): void
    {
        $root = rtrim(BuildConfig::string('workspace_root', '/var/lib/docup/workspaces'), '/');

        if (! str_starts_with($path, $root.'/') || str_contains($path, '..') || ! is_dir($path)) {
            return;
        }

        $entries = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($entries as $entry) {
            /** @var \SplFileInfo $entry */
            if ($entry->isDir() && ! $entry->isLink()) {
                @rmdir($entry->getPathname());

                continue;
            }

            @unlink($entry->getPathname());
        }

        @rmdir($path);
    }
}
