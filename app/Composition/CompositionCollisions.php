<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

/**
 * 🛑 §8.7.14's collision check, and §8.7.15's shadow redirects, from the
 * file manifests.
 *
 * In `mount` mode two components collide when one mount's prefix swallows a
 * URL the other mount's build also serves. That cannot be seen from the
 * mount paths alone — it is a question about **files** — which is why
 * §8.7.15 says the redirect rows are "identified from the affected builds'
 * file manifests" and why §8.7.14 requires the message to name "the exact
 * path".
 *
 * The geometry, once, because it is easy to get backwards. §8.7.12 resolves
 * by **longest** prefix. So for two mounts where one path prefixes the
 * other, every request under the deeper prefix goes to the deeper mount.
 * The shallower mount's files under that prefix are therefore unreachable —
 * the deeper mount **shadows** them. Which of the two was created first is
 * irrelevant; only depth matters.
 *
 * Two different things can then be true of one shadowed path:
 *
 *  - the deeper mount serves the same URL as well. That is §8.7.14's
 *    **collision**: two sources, one URL, and a reader gets whichever the
 *    resolver picks. Refused by default.
 *  - the deeper mount serves nothing there. That is §8.7.15's **shadowed
 *    path**: the content is simply gone, and the override's redirect rows
 *    are what stop a bookmark turning into a 404.
 *
 * Distinguishing them is the whole value of doing this from the manifests
 * rather than from the paths.
 */
final readonly class CompositionCollisions
{
    /**
     * 🛑 A ceiling on how many shadowed paths produce redirect rows.
     *
     * §8.8.10 caps redirects per project at 200 for a project's own rules.
     * These are generated, so they do not consume that quota — but an
     * unbounded set would put a megabyte of JSON into an immutable manifest
     * that is read on every request, which is the §8.4.18 failure mode
     * ("MUST NOT become a SQL routing table on the serving path") reached
     * through a different door. Past the cap the composition still
     * publishes and the overflow is counted, so an operator sees a number
     * rather than silence.
     */
    public const MAX_SHADOW_REDIRECTS = 500;

    /**
     * Compare every pair of mounts and return what overlaps.
     *
     * @param  list<ResolvedMount>  $mounts  resolved, each with its file list
     */
    public function inspect(array $mounts): CompositionOverlap
    {
        $collisions = [];
        $redirects = [];
        $overflow = 0;

        foreach ($mounts as $outer) {
            foreach ($mounts as $inner) {
                if ($outer === $inner) {
                    continue;
                }

                // Only the shallower mount can be shadowed. Checking one
                // direction per ordered pair also visits each unordered pair
                // once, because `prefixes()` is false in the other direction.
                if (! MountShadowing::prefixes($outer->mountPath, $inner->mountPath)) {
                    continue;
                }

                foreach ($this->shadowedPaths($outer, $inner) as $relative) {
                    $url = $this->urlFor($outer->mountPath, $relative);
                    $withinInner = MountShadowing::below($outer->mountPath, $inner->mountPath);

                    if ($withinInner === null) {
                        continue;
                    }

                    $innerRelative = MountShadowing::below($withinInner, $relative);

                    if ($innerRelative !== null && $inner->serves($innerRelative)) {
                        // Both serve it: §8.7.14's collision.
                        $collisions[] = new PathCollision($url, $outer, $inner);

                        continue;
                    }

                    // Only the shallower one served it: §8.7.15's shadow.
                    if (count($redirects) >= self::MAX_SHADOW_REDIRECTS) {
                        $overflow++;

                        continue;
                    }

                    /*
                     * The directory form, with the trailing slash. SPEC 8.9.7
                     * redirects a directory path without one, so a target of
                     * `guide` would make every shadowed path take two hops —
                     * and the second hop would be indistinguishable, in a log,
                     * from the resolver failing to find the first.
                     */
                    $redirects[$url] = $this->urlFor($inner->mountPath, '').'/';
                }
            }
        }

        return new CompositionOverlap($collisions, $redirects, $overflow);
    }

    /**
     * The shallower mount's served paths that fall under the deeper prefix.
     *
     * @return list<string> relative to the shallower mount
     */
    private function shadowedPaths(ResolvedMount $shallow, ResolvedMount $deep): array
    {
        $within = MountShadowing::below($shallow->mountPath, $deep->mountPath);

        if ($within === null || $within === '') {
            return [];
        }

        $shadowed = [];

        foreach ($shallow->documentPaths() as $path) {
            if ($path === $within || MountShadowing::prefixes($within, $path)) {
                $shadowed[] = $path;
            }
        }

        return $shadowed;
    }

    /** A path relative to the version root, as a reader would request it. */
    private function urlFor(string $mountPath, string $relative): string
    {
        $parts = array_values(array_filter([$mountPath, $relative], static fn (string $p): bool => $p !== ''));

        return implode('/', $parts);
    }
}
