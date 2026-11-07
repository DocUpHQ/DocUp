<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Serving;

use App\Http\Middleware\RejectNonCanonicalPath;
use App\Seo\GeneratedStore;
use App\Seo\RobotsTxt;
use App\Serving\ArtifactHandoff;
use App\Serving\CachePolicy;
use App\Serving\ManifestReader;
use App\Serving\RoutingSnapshotLoader;
use App\Serving\SnapshotMount;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * §8.11.6's four generated files, at a domain mount's root.
 *
 * 🛑 **Why these need a route of their own at all.** §7.3's grammar is
 * `host → domain_mount(path_prefix) → project → [url_prefix] →
 * {lang}/{version} → component_mount → file`, so every served document sits
 * under a language and a version. `robots.txt` does not: a crawler asks for
 * it at the root of the host and nothing else will do. It is therefore
 * outside the grammar rather than a special case inside it — the same
 * treatment §7.3 gives `/_/` and `/.well-known/`.
 *
 * 🛑 **"A build-shipped file MUST always win."** The clause cannot be
 * satisfied by route ordering here, because a generator's `robots.txt`
 * lands in its output root and is served at `/{lang}/{version}/robots.txt`
 * — a different URL from the one a crawler asks for. So the precedence is
 * an explicit probe: the default version's file manifest is consulted
 * first, and a shipped file is **handed off by the edge** exactly as any
 * other documentation byte is (§4.3/2), not read and echoed by PHP.
 *
 * 🛑 **`X-Robots-Tag: noindex` as well as `Disallow: /`** on every
 * non-canonical mount. Two mechanisms for one intention, read at different
 * moments: the file stops the fetch, the header stops the indexing of a
 * page fetched before the file was read or reached through a link that
 * never consulted it. §8.11.6 asks for both; the redundancy is the
 * requirement.
 */
final class GeneratedFileController
{
    public function __construct(
        private readonly RoutingSnapshotLoader $snapshots,
        private readonly ManifestReader $manifests,
        private readonly GeneratedStore $store,
        private readonly ArtifactHandoff $handoff,
        private readonly DocumentController $documents,
    ) {}

    /**
     * 🛑 The filename is read **by name** from the route, never positionally.
     *
     * Phase 19 recorded this trap and Phase 20 walked into it anyway: Laravel
     * passes a route's **domain** parameters before its path parameters, so a
     * controller declaring `string $docupGeneratedFile` on a route under
     * `Route::domain('{docupHostLabel}.'.$apex)` receives the **host label** in
     * it. Both groups that register these routes are domain-scoped — the
     * default subdomain and the custom host — so all four generated files
     * answered `generated.unknown_file` on every host there has ever been.
     *
     * Found by Phase 21's first HTTP request for a `sitemap.xml`. Phase 20's
     * own tests drove `GeneratedArtifacts` and the store directly and asserted
     * the written bytes, which were correct; nothing asked for one over HTTP.
     * `tests/Feature/Seo/GeneratedArtifactsTest` now does, on both host shapes.
     */
    public function __invoke(Request $request): Response
    {
        $file = (string) $request->route('docupGeneratedFile');

        if (! in_array($file, GeneratedStore::FILES, true)) {
            return $this->absent('generated.unknown_file');
        }

        $snapshot = $this->snapshots->load((string) $request->getHost());
        $path = RejectNonCanonicalPath::rawPath($request);

        /*
         * The mount is matched on the path prefix alone — there is no
         * version in this URL to resolve — so `/docs/robots.txt` belongs to
         * the `/docs` mount and `/robots.txt` on the same host belongs to
         * whatever is at the root. §8.11.6's "per domain mount" is this
         * line.
         */
        $mount = $this->mountFor($snapshot->mounts, $path, $file);

        if ($mount === null) {
            /*
             * 🛑 The prefix names no mount, so this is **not** a generated
             * file at all — it is a documentation path that happens to end
             * in one of the four names, such as
             * `/en/v1/sitemap.xml` shipped by a generator. The route
             * pattern could not tell, because mount prefixes are rows.
             *
             * Delegated rather than 404'd, and that is the difference
             * between this route being a feature and being a hole: a 404
             * here would make these four filenames unservable from any
             * build, for every project, for ever.
             */
            return $this->documents->__invoke($request);
        }

        $shipped = $this->buildShippedKey($mount, $file);

        if ($shipped !== null) {
            return $this->handoff->respond($shipped, [
                RejectNonCanonicalPath::RESOLVER_HEADER => 'generated.build_shipped',
                'X-Content-Type-Options' => 'nosniff',
                ...$this->noindex($mount),
                ...CachePolicy::forAbsence(
                    projectIsPublic: $mount->project->visibility === 'public',
                    versionIsPublic: true,
                )->headers(),
            ]);
        }

        $contents = $this->store->get((string) $mount->id, $mount->generatedRevision, $file);

        if ($contents === null) {
            /*
             * 🛑 `robots.txt` is the one file whose absence must be
             * answered rather than reported, because a 404 means "crawl
             * everything". A mount that has never published has no
             * generated set, and so does a serving alias added since the
             * last publish — so the default is computed from the mount's
             * own `is_indexable`, which §8.10.2 derives from the mode and
             * the routing snapshot already carries.
             */
            if ($file === 'robots.txt') {
                return $this->text(
                    RobotsTxt::render($mount->isIndexable, null),
                    $file,
                    $mount,
                    'generated.default_robots',
                );
            }

            return $this->absent('generated.not_written');
        }

        return $this->text($contents, $file, $mount, 'generated.store');
    }

    /**
     * The storage key of a build-shipped copy, or null.
     *
     * 🛑 The **default version's** build, and only the mount's primary
     * component. A generator ships one `robots.txt` for its own output; a
     * composed project with four components could ship four, and picking
     * among them would be DocUp inventing a precedence nobody asked for.
     * The primary mount is the project's own root (§8.7.6 makes it the one
     * that owns `/`), so its copy is the project's answer.
     */
    private function buildShippedKey(SnapshotMount $mount, string $file): ?string
    {
        $version = $mount->project->defaultVersionId === null
            ? null
            : $this->defaultVersion($mount);

        if ($version === null) {
            return null;
        }

        foreach ($this->manifests->mounts($version) as $componentMount) {
            if ($componentMount['build_id'] === null || ! $componentMount['is_primary']) {
                continue;
            }

            if (isset($this->manifests->files($componentMount['build_id'])[$file])) {
                return $this->manifests->storageKeyFor($componentMount['build_id'], $file);
            }
        }

        return null;
    }

    /** The published manifest id of the project's default version, or null. */
    private function defaultVersion(SnapshotMount $mount): ?string
    {
        foreach ($mount->project->versions as $version) {
            if ($version->id === $mount->project->defaultVersionId) {
                return $version->publishedManifestId;
            }
        }

        return null;
    }

    /**
     * @param  list<SnapshotMount>  $mounts
     */
    private function mountFor(array $mounts, string $path, string $file): ?SnapshotMount
    {
        $prefix = substr($path, 0, strlen($path) - strlen($file) - 1);
        $prefix = $prefix === '' ? '' : rtrim($prefix, '/');

        $best = null;

        foreach ($mounts as $mount) {
            if ($mount->mode === 'redirect') {
                continue;
            }

            if (rtrim($mount->pathPrefix, '/') === $prefix) {
                /*
                 * An exact prefix match is the answer, and there is at most
                 * one: §10.5 puts `UNIQUE (domain_id, path_prefix)` on the
                 * table.
                 */
                return $mount;
            }

            if ($prefix === '' && $mount->pathPrefix === '') {
                $best = $mount;
            }
        }

        return $best;
    }

    /** @return array<string, string> */
    private function noindex(SnapshotMount $mount): array
    {
        return $mount->isIndexable ? [] : ['X-Robots-Tag' => 'noindex'];
    }

    private function text(string $contents, string $file, SnapshotMount $mount, string $rule): Response
    {
        return response($contents, 200, [
            'Content-Type' => $file === 'sitemap.xml'
                ? 'application/xml; charset=utf-8'
                : 'text/plain; charset=utf-8',
            RejectNonCanonicalPath::RESOLVER_HEADER => $rule,
            'X-Content-Type-Options' => 'nosniff',
            ...$this->noindex($mount),
            ...CachePolicy::forAbsence(
                projectIsPublic: $mount->project->visibility === 'public',
                versionIsPublic: true,
            )->headers(),
        ]);
    }

    private function absent(string $rule): Response
    {
        return response('', 404, [
            RejectNonCanonicalPath::RESOLVER_HEADER => $rule,
            'X-Content-Type-Options' => 'nosniff',
            ...CachePolicy::forAbsence()->headers(),
        ]);
    }
}
