<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * 🛑 §7.3's path grammar, in full, purely.
 *
 * ```
 * host
 *   → domain_mount(path_prefix)        longest match, on a segment boundary
 *   → project
 *   → [project.url_prefix]
 *   → {lang}/{version} | {version} | ∅  per project.versioning_scheme
 *   → component_mount(mount_path)      longest match, on a segment boundary
 *   → relative file path
 * ```
 *
 * §8.9.1: "**one pure resolver** taking a pre-loaded routing snapshot, with no
 * database queries and no framework dependencies, implementing the §7.3 grammar
 * in full from the phase it first ships. It MUST sustain ≥95% branch coverage
 * and ≥80% mutation score."
 *
 * **Why the grammar is implemented in two calls.** The last two steps need the
 * published file manifest, and which manifest that is cannot be known until the
 * version step has run. So {@see self::resolveRoute()} walks the grammar down to
 * the version and hands back the remainder; the caller loads that version's
 * manifest — one lookup, cached — and {@see self::resolveFile()} finishes.
 * Both halves are pure and neither touches a database; the sequencing lives in
 * the caller, where the one lookup is visible.
 *
 * 🛑 This class is frozen at the end of Phase 04 (§17.4). The freeze "is only
 * honest because P04 implements the **full** grammar — domain-mount prefix,
 * project URL prefix, version segment, component-mount prefix, reserved
 * namespace — and later phases merely populate tables." Changing it afterwards
 * requires an ADR.
 */
final class Resolver
{
    /**
     * §7.3's reserved first segments, which are unmountable.
     *
     * "`/_/` and `/.well-known/` are reserved first segments, unmountable.
     * Nothing under `/_/` is publicly cacheable." They are refused here rather
     * than resolved, because they are not documentation: the edge routes them
     * to their own endpoints before the document proxy is reached, and a
     * resolver that claimed them would make a project called `_` able to
     * shadow `/_/search`.
     */
    private const RESERVED_SEGMENTS = ['_', '.well-known'];

    /**
     * Walk the grammar from the host down to the version.
     *
     * The path must already have passed {@see CanonicalPath::reject()}. That
     * ordering is §8.9.6's — "before any cache lookup or resolution" — and this
     * method deliberately does not re-check it: a second check here would
     * suggest the first one were optional.
     *
     * @param  string  $path  canonical, leading slash included
     */
    public function resolveRoute(RoutingSnapshot $snapshot, string $path): RouteOutcome
    {
        /*
         * 🛑 §8.10.6: "Suspended and unverified hosts MUST be neither served
         * nor certified." Checked first, so an unverified host cannot reach
         * even the mount list — which is what stops a half-configured custom
         * domain serving content while its DNS proof is still pending.
         */
        if (! $snapshot->servable) {
            return RouteOutcome::rejected('host.not_servable', RejectionReason::HostNotServable);
        }

        if ($snapshot->mounts === []) {
            /*
             * 🛑 §8.9.3: "It MUST NEVER fall through to a default project." A
             * host with no mounts is a hard 404 — which is what makes a
             * dangling CNAME pointed at this installation serve nothing rather
             * than somebody else's documentation.
             */
            return RouteOutcome::rejected('host.no_mounts', RejectionReason::HostNotFound);
        }

        $relative = ltrim($path, '/');
        $firstSegment = $relative === '' ? '' : explode('/', $relative)[0];

        if (in_array($firstSegment, self::RESERVED_SEGMENTS, true)) {
            return RouteOutcome::rejected('path.reserved', RejectionReason::ReservedSegment);
        }

        // Step 1: the domain mount, longest prefix on a segment boundary.
        $match = $snapshot->matchFor($path);

        if ($match === null) {
            return RouteOutcome::rejected('mount.no_match', RejectionReason::MountNotFound);
        }

        $mount = $match->mount;

        if ($mount->mode === 'redirect') {
            /*
             * §8.10.2's third mode. The redirect target is the project's
             * canonical mount, which the caller knows and this class does not:
             * a pure resolver cannot build an absolute URL without being told
             * the canonical host, and passing it in only to echo it back would
             * be ceremony. The caller sees `mode` on the returned mount.
             */
            return RouteOutcome::rejected('mount.redirect_mode', RejectionReason::MountNotFound);
        }

        /*
         * No second strip. SegmentPrefix matched and consumed in one operation,
         * so there is nothing here that could disagree with the match — which
         * is what let the defensive `mount.prefix_mismatch` branch go.
         */
        $afterMount = $match->remainder;

        // Steps 2 and 3: the project is the mount's, and its optional prefix.
        $project = $mount->project;

        /*
         * 🛑 The mount root is handled BEFORE the project prefix, and the
         * ordering is the fix for a real mistake. With the prefix step first,
         * `/portal` on a mount at `portal` for a project prefixed `docs` was
         * refused as a prefix mismatch — so the portal's own root 404'd, which
         * is not what §8.9.7's "An empty path MUST 302 to the default version"
         * asks for. An empty path is empty relative to its mount; the prefix is
         * something the redirect ADDS, not something the request must already
         * carry.
         */
        if ($afterMount === '') {
            $root = $this->rootRedirect($mount, $path);

            if ($root !== null) {
                return $root;
            }

            // Already canonical — a `single_version` project with no prefixes,
            // where the root IS the document. Fall through with nothing left.
            return $this->resolveVersion($mount, '', $path);
        }

        if ($project->urlPrefix !== null && $project->urlPrefix !== '') {
            $afterPrefix = $this->strip($afterMount, $project->urlPrefix);

            if ($afterPrefix === null) {
                return RouteOutcome::rejected('project.prefix_mismatch', RejectionReason::ProjectPrefixMismatch);
            }

            $afterMount = $afterPrefix;
        }

        // Step 4: the version segments, per the scheme in force.
        return $this->resolveVersion($mount, $afterMount, $path);
    }

    /**
     * The §8.9.7 redirect for a request at a mount root, or null when the root
     * is already canonical.
     *
     * 🛑 The null case is a redirect loop averted. A `single_version` project
     * with no prefixes has a canonical root of `/`, so redirecting `/` to the
     * default version would redirect it to itself — forever. Comparing the
     * target against the request is what makes the rule "add what is missing"
     * rather than "always redirect".
     */
    private function rootRedirect(SnapshotMount $mount, string $path): ?RouteOutcome
    {
        $version = $mount->project->defaultVersion();

        if ($version === null) {
            return RouteOutcome::rejected('version.no_default', RejectionReason::VersionNotFound);
        }

        $target = $this->versionPath($mount, $mount->versioningScheme(), $version);

        if ($target === $path || $target === rtrim($path, '/').'/') {
            return null;
        }

        return RouteOutcome::redirect('version.default_redirect', $target);
    }

    /**
     * §7.3's fifth step: the component mount, longest match on a boundary.
     *
     * Separate from {@see self::resolveFile()} because each mount resolves to
     * its own build and therefore its own file manifest — see {@see MountMatch}
     * for what that fixed. The caller loads the matched build's manifest
     * between the two calls, which is also where the single storage read
     * belongs: visible, rather than hidden inside a resolver that §8.9.1
     * requires to make none.
     *
     * @param  list<array{mount_path: string, build_id: string|null}>  $mounts
     *                                                                          the version manifest's component mounts
     * @param  string  $remainder  what {@see self::resolveRoute()} left over
     */
    public function resolveMount(array $mounts, string $remainder): ?MountMatch
    {
        $match = SegmentPrefix::longest(
            array_map(static fn (array $mount): string => $mount['mount_path'], $mounts),
            $remainder,
        );

        if ($match === null) {
            return null;
        }

        [$prefix, $within] = $match;

        foreach ($mounts as $mount) {
            if ($mount['mount_path'] === $prefix) {
                return new MountMatch($prefix, $mount['build_id'], $within);
            }
        }

        // Unreachable: the prefix came from this list.
        return null;
    }

    /**
     * §7.3's last step: the file, from the matched component's manifest.
     *
     * @param  array<string, array{sha256: string, bytes: int, content_type: string}>  $manifestFiles
     *                                                                                                 the matched build's manifest `files` map, keyed by
     *                                                                                                 path relative to `builds/{build_id}/`
     */
    public function resolveFile(array $manifestFiles, MountMatch $match): FileOutcome
    {
        $within = $match->within;

        /*
         * §8.9.7: "a directory path MUST resolve `index.html` and 302 to the
         * slash form."
         *
         * Two behaviours, and the order matters. A path already ending in `/`
         * is the directory form, so `index.html` is appended and served. A path
         * NOT ending in `/` that names a directory gets a 302 to the slash form
         * — never the index served directly, because serving it would make
         * every relative link in the document resolve one level too high.
         */
        if ($within === '' || str_ends_with($within, '/')) {
            $candidate = 'html/'.$within.'index.html';

            if (isset($manifestFiles[$candidate])) {
                return FileOutcome::file($candidate, $manifestFiles[$candidate], $match->buildId);
            }

            return FileOutcome::rejected(RejectionReason::FileNotFound);
        }

        $key = 'html/'.$within;

        if (isset($manifestFiles[$key])) {
            return FileOutcome::file($key, $manifestFiles[$key], $match->buildId);
        }

        // Not a file. If it is a directory — something in the manifest lives
        // under it — the answer is the slash redirect, not a 404.
        if ($this->isDirectory($manifestFiles, $key)) {
            return FileOutcome::directory($within.'/');
        }

        return FileOutcome::rejected(RejectionReason::FileNotFound);
    }

    /**
     * Step 4 of the grammar: `{lang}/{version}`, `{version}`, or nothing.
     */
    private function resolveVersion(SnapshotMount $mount, string $remainder, string $originalPath): RouteOutcome
    {
        $scheme = $mount->versioningScheme();
        $project = $mount->project;

        if ($scheme === 'single_version') {
            /*
             * §8.6.9's `single_version`: no segments are consumed, and the
             * default version answers everything. The pointer is still
             * consulted rather than guessed, because §8.6.14 makes it explicit
             * and a project with no default version serves nothing.
             */
            $version = $project->defaultVersion();

            if ($version === null) {
                return RouteOutcome::rejected('version.no_default', RejectionReason::VersionNotFound);
            }

            return RouteOutcome::resolved('version.single', $mount, $version, $version->language, $remainder);
        }

        /*
         * §8.9.7: "An empty path MUST 302 to the default version". The redirect
         * is relative to the mount, so a project mounted under a path prefix
         * keeps it.
         */
        if ($remainder === '') {
            $version = $project->defaultVersion();

            if ($version === null) {
                return RouteOutcome::rejected('version.no_default', RejectionReason::VersionNotFound);
            }

            $target = $this->versionPath($mount, $scheme, $version);

            return RouteOutcome::redirect('version.default_redirect', $target);
        }

        $segments = explode('/', $remainder);

        if ($scheme === 'lang_and_version') {
            if (count($segments) < 2) {
                /*
                 * `/en` alone names a language and no version. Not a redirect:
                 * guessing a version here would make `/en` and `/en/latest/`
                 * two URLs for one page, and §8.9.6's whole point is that a
                 * document has one URL.
                 */
                return RouteOutcome::rejected('version.missing_segment', RejectionReason::VersionNotFound);
            }

            $language = $segments[0];
            $versionSlug = $segments[1];
            $rest = implode('/', array_slice($segments, 2));
        } else {
            $language = '';
            $versionSlug = $segments[0];
            $rest = implode('/', array_slice($segments, 1));
        }

        if (! $mount->exposes($versionSlug)) {
            // §10.5's version_scope: this mount is configured not to show it.
            // 404 rather than 403, for the same reason §8.2.2 gives: whether a
            // version exists elsewhere is not this mount's business to reveal.
            return RouteOutcome::rejected('version.out_of_scope', RejectionReason::VersionNotFound);
        }

        if ($scheme === 'lang_and_version' && ! $project->hasLanguage($language)) {
            return RouteOutcome::rejected('language.no_match', RejectionReason::LanguageNotFound);
        }

        $version = $scheme === 'lang_and_version'
            ? $project->version($language, $versionSlug)
            : $this->versionBySlug($project, $versionSlug);

        if ($version === null) {
            return RouteOutcome::rejected('version.no_match', RejectionReason::VersionNotFound);
        }

        if (! $version->isServable()) {
            /*
             * Inactive, unpublished, or published with no manifest. All three
             * answer 404: §8.6.2 keeps the axes independent, and a reader
             * cannot be told which axis excluded them without leaking the
             * version's existence and its state.
             */
            return RouteOutcome::rejected('version.not_servable', RejectionReason::NothingPublished);
        }

        /*
         * A version root with no trailing slash — `/en/latest` — is the
         * directory case of §8.9.7 at the version level. Redirected rather than
         * served, so relative links in `index.html` resolve against
         * `/en/latest/` and not against `/en/`.
         */
        if ($rest === '' && ! str_ends_with($originalPath, '/')) {
            return RouteOutcome::redirect('version.slash_redirect', $this->versionPath($mount, $scheme, $version));
        }

        return RouteOutcome::resolved('version.matched', $mount, $version, $version->language, $rest);
    }

    /**
     * The canonical path of a version root, for a redirect target.
     */
    private function versionPath(SnapshotMount $mount, string $scheme, SnapshotVersion $version): string
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
     * A version by slug alone, for `multi_version`.
     *
     * 🛑 Ambiguous by construction once a project has translations, because
     * §10.4's unique key is `(project_id, language, slug)`. Resolved by
     * preferring the default version's language and otherwise taking the
     * lowest language code, so the answer is at least deterministic — a project
     * serving translations under `multi_version` is a misconfiguration §8.6.9
     * does not forbid, and an arbitrary answer would make it an intermittent
     * one.
     */
    private function versionBySlug(SnapshotProject $project, string $slug): ?SnapshotVersion
    {
        $preferred = $project->defaultVersion()?->language;
        $matches = [];

        foreach ($project->versions as $version) {
            if ($version->slug === $slug) {
                $matches[$version->language] = $version;
            }
        }

        if ($matches === []) {
            return null;
        }

        if ($preferred !== null && isset($matches[$preferred])) {
            return $matches[$preferred];
        }

        // Lowest language code wins, so the answer is deterministic rather
        // than whichever row the database happened to return first.
        ksort($matches, SORT_STRING);

        return $matches[(string) array_key_first($matches)];
    }

    /**
     * Remove a prefix, requiring the match to end on a segment boundary.
     *
     * Returns null when the prefix does not match, and the remainder — with no
     * leading slash — when it does. The boundary requirement is §7.3's and is
     * the same rule {@see RoutingSnapshot::mountFor()} applies; it lives in two
     * places because one of them is choosing a mount and the other is consuming
     * one, and collapsing them would mean the chooser also mutated the path.
     */
    private function strip(string $path, string $prefix): ?string
    {
        if ($prefix === '') {
            return $path;
        }

        if ($path === $prefix) {
            return '';
        }

        if (! str_starts_with($path, $prefix.'/')) {
            return null;
        }

        return substr($path, strlen($prefix) + 1);
    }

    /**
     * Whether anything in the manifest lives under this key as a directory.
     *
     * 🛑 Answered from the manifest, never from storage. §8.4.18 requires the
     * 404 chain to work "**without a storage existence probe per request**",
     * and a `HEAD` to an object store per 404 is both the latency and the bill
     * this design exists to avoid.
     *
     * @param  array<string, array{sha256: string, bytes: int, content_type: string}>  $files
     */
    private function isDirectory(array $files, string $key): bool
    {
        $needle = $key.'/';

        foreach (array_keys($files) as $path) {
            if (str_starts_with($path, $needle)) {
                return true;
            }
        }

        return false;
    }
}
