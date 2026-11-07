<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * §7.3's path, built rather than parsed — the one implementation.
 *
 * 🛑 **Extracted from {@see Resolver}, not written beside it.** §17.4 freezes
 * the resolver and the §7.3 grammar at the end of Phase 04, and the thing that
 * freeze protects is there being *one* statement of the grammar. Phase 16
 * needs to build version URLs outside the resolver — a language switcher, a
 * collection flyout and §8.11.6's `hreflang` alternates are all lists of URLs
 * for documents nobody requested — and the way to get them without a second
 * implementation is to move the resolver's own `versionPath()` here and have
 * it call this. The resolver's behaviour is unchanged; its suite proves it.
 *
 * Pure, like the resolver: no database, no framework, no configuration.
 */
final class VersionUrl
{
    /**
     * The canonical path of a version root, with its trailing slash.
     *
     * The parts are §7.3's, in order: the domain mount's prefix, the
     * project's optional URL prefix, the language where the scheme carries
     * one, and the version slug where the scheme carries one. Empty parts
     * drop out, so a project at a host root under `single_version` gets `/`.
     */
    public static function root(SnapshotMount $mount, string $scheme, SnapshotVersion $version): string
    {
        $parts = array_filter([
            $mount->pathPrefix,
            $mount->project->urlPrefix ?? '',
            $scheme === 'lang_and_version' ? $version->language : '',
            $scheme === 'single_version' ? '' : $version->slug,
        ], static fn (string $part): bool => $part !== '');

        return '/'.($parts === [] ? '' : implode('/', $parts).'/');
    }

    /**
     * The path of a document inside a version.
     *
     * `$within` is relative to the version root — what
     * {@see RouteOutcome::$remainder} carries — so passing `''` returns the
     * version root itself. No normalisation happens here: a caller holding a
     * remainder got it from the resolver, which got it from a path
     * {@see CanonicalPath} already refused if it was not canonical.
     */
    public static function document(
        SnapshotMount $mount,
        string $scheme,
        SnapshotVersion $version,
        string $within,
    ): string {
        return self::root($mount, $scheme, $version).$within;
    }

    /**
     * Everything §7.3 puts **before** `{lang}/{version}`: the mount's path
     * prefix and the project's URL prefix, concatenated, with no trailing
     * slash.
     *
     * 🛑 Here rather than in the caller because it is the inverse of
     * {@see self::root()} and §4.3 allows one statement of the grammar. A
     * second place that stripped prefixes would be a second place that
     * could disagree with the place that builds them — and a redirect
     * whose pattern space is off by a prefix matches nothing, silently.
     */
    public static function shed(SnapshotMount $mount): string
    {
        $parts = array_filter([
            trim($mount->pathPrefix, '/'),
            trim($mount->project->urlPrefix ?? '', '/'),
        ], static fn (string $part): bool => $part !== '');

        return $parts === [] ? '' : '/'.implode('/', $parts);
    }

    /**
     * A request path as a §8.11.2 redirect rule sees it: the mount's and
     * the project's prefixes removed, `{lang}/{version}` still present.
     *
     * 🛑 **This is the pattern space, and choosing it is a decision.** An
     * operator writes `/en/v2/guide/page.html`, not
     * `/docs/handbook/en/v2/guide/page.html` — they do not know and should
     * not have to know where the project is mounted, because the mount can
     * move and the rules must survive it. §8.11's subject is URLs that
     * survive reorganisation, and a rule set invalidated by the project's
     * own relocation would be the first thing to fail that.
     */
    public static function within(SnapshotMount $mount, string $path): string
    {
        $shed = self::shed($mount);

        if ($shed === '' || ! str_starts_with($path, $shed)) {
            return $path;
        }

        $rest = substr($path, strlen($shed));

        return $rest === '' ? '/' : $rest;
    }
}
