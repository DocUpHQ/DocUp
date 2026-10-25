<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Serving;

use App\Serving\ArtifactHandoff;
use App\Serving\ManifestReader;
use App\Serving\RoutingSnapshotLoader;
use App\Serving\SnapshotMount;
use App\Serving\SnapshotVersion;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * 🛑 §8.7.16's cross-component reference namespace.
 *
 * > "Cross-component links MUST resolve at serve time through
 * > `/_/x/{component_key}/{path}` against the published manifest, 302'd and
 * > edge-cacheable. `objects.inv` and a per-component cross-reference map
 * > MUST be served **directly at a stable path with no redirect**, so Sphinx
 * > intersphinx never depends on redirect-following."
 *
 * Two behaviours, and the split is the requirement's. A human-facing link is
 * a **302** to wherever the component is mounted today, because a mount path
 * is a project's decision and can change without any build changing — which
 * is also what makes the redirect cacheable at the edge and invalidated by
 * the routing epoch rather than by a rebuild. An intersphinx inventory is
 * served **directly**, because Sphinx's fetcher does not follow redirects
 * reliably and a tool that breaks on a 302 breaks silently, a year later,
 * in somebody else's build.
 *
 * 🛑 **The version is the project's default, and that is a known limit.**
 * The URL §8.7.16 specifies carries no version segment, and it cannot: a
 * build emits these hrefs, and §8.7.10 forbids project-scoped input —
 * including the version — from entering a build container. So one
 * `/_/x/glossary/terms.html` has to mean one thing, and the only
 * version-independent answer is the default version's composition. §8.7.17's
 * client-side rewrite is what gets a reader of v1 to v1's glossary; this is
 * the no-JavaScript and AI-agent path, and it lands on the default. Recorded
 * as a proposed amendment to §8.7.16 rather than worked around with a
 * `Referer` sniff, which would make the response uncacheable and so break
 * the clause's other half.
 */
final class CrossReferenceController
{
    /**
     * Sphinx's inventory, and DocUp's own map, both served without a redirect.
     *
     * Named here rather than matched by extension so the set is closed: any
     * other path under `/_/x/{key}/` is a document reference and gets the
     * 302.
     */
    private const DIRECT_PATHS = ['objects.inv', '_xref.json'];

    /**
     * Every response from this controller, and see {@see self::redirect()}
     * for why even the 302 carries it.
     */
    private const NO_STORE = 'no-store';

    public function __construct(
        private readonly RoutingSnapshotLoader $snapshots,
        private readonly ManifestReader $manifests,
        private readonly ArtifactHandoff $handoff,
    ) {}

    public function __invoke(
        Request $request,
        string $docupHostLabel,
        string $component,
        string $path = '',
    ): Response {
        $snapshot = $this->snapshots->load((string) $request->getHost());

        if (! $snapshot->servable || $snapshot->mounts === []) {
            return $this->notFound();
        }

        $mount = $snapshot->mounts[0];
        $version = $mount->project->defaultVersion();

        if (! $version instanceof SnapshotVersion || $version->publishedManifestId === null) {
            return $this->notFound();
        }

        $map = $this->manifests->crossReferences($version->publishedManifestId);
        $entry = $map[strtolower($component)] ?? null;

        if ($entry === null) {
            /*
             * §8.7.16 records an unresolved reference as a publish-time link
             * issue; at request time the honest answer is simply that the
             * component is not part of this version. 404 rather than a
             * redirect to the version root, because §8.9.6's whole argument
             * is that a URL names one document, and sending every typo to
             * the home page is how a broken link becomes invisible.
             */
            return $this->notFound();
        }

        if (in_array($path, self::DIRECT_PATHS, true)) {
            return $this->direct($entry, $version, $path);
        }

        return $this->redirect($mount, $version, $entry['mount_path'], $path);
    }

    /**
     * 🛑 The direct half: no redirect, because intersphinx must not need one.
     *
     * `_xref.json` is answered from the manifest, which is already in
     * memory. `objects.inv` is a build artifact, so it goes through the
     * same §8.9.8 handoff every document uses — the application names a
     * path and never reads a byte.
     *
     * @param  array{mount_path: string, build_id: string|null, objects_inv: bool}  $entry
     */
    private function direct(array $entry, SnapshotVersion $version, string $path): Response
    {
        if ($path === '_xref.json') {
            return response()->json(
                [
                    'schema' => 'docup.xref-map/1',
                    'components' => $this->manifests->crossReferences((string) $version->publishedManifestId),
                ],
                200,
                [
                    'Cache-Control' => self::NO_STORE,
                    'X-Content-Type-Options' => 'nosniff',
                ],
            );
        }

        if (! $entry['objects_inv'] || $entry['build_id'] === null) {
            return $this->notFound();
        }

        $files = $this->manifests->files($entry['build_id']);
        $file = $files['html/objects.inv'] ?? null;

        if ($file === null) {
            return $this->notFound();
        }

        return $this->handoff->respond(
            $this->manifests->storageKeyFor($entry['build_id'], 'html/objects.inv'),
            [
                /*
                 * `application/octet-stream` rather than the manifest's
                 * guess. `objects.inv` is a zlib-compressed binary behind a
                 * plain-text header, and a type that invited a browser to
                 * render it would hand a reader mojibake — intersphinx reads
                 * bytes and does not care.
                 */
                'Content-Type' => 'application/octet-stream',
                'Cache-Control' => self::NO_STORE,
                'X-Content-Type-Options' => 'nosniff',
                'ETag' => '"'.substr($file['sha256'], 0, 32).'"',
            ],
        );
    }

    /**
     * The 302 half: where this component is mounted in the default version.
     */
    private function redirect(
        SnapshotMount $mount,
        SnapshotVersion $version,
        string $mountPath,
        string $path,
    ): Response {
        $parts = array_values(array_filter([
            $mount->pathPrefix,
            $mount->project->urlPrefix ?? '',
            $mount->versioningScheme() === 'lang_and_version' ? $version->language : '',
            $mount->versioningScheme() === 'single_version' ? '' : $version->slug,
            $mountPath,
            $path,
        ], static fn (string $part): bool => $part !== ''));

        return response('', 302, [
            'Location' => '/'.implode('/', $parts),

            /*
             * 🛑 **`no-store`, and §8.7.16 asks for "edge-cacheable".** The
             * two requirements disagree and §7.3 is the stricter of the
             * two: "Nothing under `/_/` is publicly cacheable", stated
             * without exception and applying to this path by construction.
             *
             * Following §7.3 is also the only safe reading today, because
             * reader authorisation is Phase 21's: whether a component is
             * mounted on a project is information, and a shared cache
             * holding that answer would hold it for readers who may not be
             * entitled to it once §8.12 exists. Recorded as a proposed
             * amendment — §8.7.16's cacheability needs §7.3 to carve out
             * this namespace explicitly, and it can only do so once there
             * is an authorisation decision to carve around.
             */
            'Cache-Control' => self::NO_STORE,
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }

    private function notFound(): Response
    {
        return response('', 404, [
            'Cache-Control' => self::NO_STORE,
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }
}
