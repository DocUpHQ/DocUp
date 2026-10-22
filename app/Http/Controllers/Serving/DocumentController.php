<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Serving;

use App\Artifacts\ContentTypes;
use App\Http\Middleware\RejectNonCanonicalPath;
use App\Serving\ArtifactHandoff;
use App\Serving\CachePolicy;
use App\Serving\FileKind;
use App\Serving\ManifestReader;
use App\Serving\RejectionReason;
use App\Serving\Resolver;
use App\Serving\RouteKind;
use App\Serving\RoutingSnapshotLoader;
use App\Support\Uuid;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The document proxy: authorise, then hand the bytes to the edge (§8.9).
 *
 * 🛑 This class never reads a documentation byte. §8.9.8: "Documentation bytes
 * MUST NOT be read by application code. The application authorises and then
 * hands off by internal redirect." An architecture test forbids every file
 * function in `App\Serving`, and the only thing this controller sends is a
 * header naming a path.
 *
 * The sequence, and why it is this order:
 *
 * 1. The §8.9.6 path check has already run, in middleware, before anything
 *    else. Its position is the whole of its value.
 * 2. Resolve the host to a routing snapshot — one query, by host alone (§8.9.4).
 * 3. Resolve the path against it, purely (§8.9.1).
 * 4. Read the version manifest and the matched build's file manifest, both
 *    immutable and both cached (§8.8.3, §8.4.18).
 * 5. Answer `304` from the manifest digest **before any handoff** (§8.9.9).
 * 6. Decide cacheability through the single three-way check (§9.3.2).
 * 7. Hand off.
 *
 * Step 5 before step 7 is the one that saves the most work: a repeat reader
 * gets a 304 without the edge touching storage at all.
 */
final class DocumentController
{
    public function __construct(
        private readonly RoutingSnapshotLoader $snapshots,
        private readonly Resolver $resolver,
        private readonly ManifestReader $manifests,
        private readonly ArtifactHandoff $handoff,
    ) {}

    public function __invoke(Request $request): Response
    {
        $path = RejectNonCanonicalPath::rawPath($request);
        $snapshot = $this->snapshots->load((string) $request->getHost());

        $route = $this->resolver->resolveRoute($snapshot, $path);

        if ($route->kind === RouteKind::Redirect) {
            return $this->redirect((string) $route->redirectTo, $route->matchedRule);
        }

        if ($route->kind === RouteKind::Rejected) {
            return $this->refuse($route->reason ?? RejectionReason::HostNotFound, $route->matchedRule);
        }

        $version = $route->version;
        $mount = $route->mount;

        if ($version === null || $mount === null || $version->publishedManifestId === null) {
            // resolveRoute() guarantees all three on a Resolved outcome. Kept
            // as a narrowing rather than an assumption: a 404 is the safe
            // answer if that guarantee is ever weakened, and a type error on
            // the serving path is not.
            return $this->refuse(RejectionReason::NothingPublished, 'version.not_servable');
        }

        $mounts = $this->manifests->mounts($version->publishedManifestId);
        $match = $this->resolver->resolveMount($mounts, $route->remainder);

        if ($match === null || $match->buildId === null) {
            return $this->refuse(RejectionReason::MountNotFound, 'component.no_match');
        }

        $file = $this->resolver->resolveFile($this->manifests->files($match->buildId), $match);

        if ($file->kind === FileKind::Directory) {
            // §8.9.7's slash form, rebuilt as an absolute path so the redirect
            // keeps every prefix the request carried.
            return $this->redirect(
                rtrim($path, '/').'/',
                'file.directory_redirect',
            );
        }

        if ($file->kind === FileKind::Rejected) {
            return $this->refuse($file->reason ?? RejectionReason::FileNotFound, 'file.no_match');
        }

        $etag = $file->etag();
        $entry = $file->entry;

        if ($file->key === null || $etag === null || $entry === null) {
            return $this->refuse(RejectionReason::FileNotFound, 'file.no_storage_key');
        }

        // §8.8.1's prefix is built by the artifact store and nowhere else; the
        // manifest path is the rest of the key.
        $storageKey = $this->manifests->storageKeyFor($match->buildId, $file->key);

        /*
         * 🛑 §8.9.9: "`304` MUST be answerable from the manifest digest before
         * any handoff." Answered here, so a repeat reader costs one manifest
         * lookup and no storage access at all — which is the difference between
         * a cheap revalidation and the edge opening a file to compute an ETag it
         * was about to be told.
         */
        $directives = CachePolicy::decide(
            projectIsPublic: $mount->project->visibility === 'public',
            versionIsPublic: $version->visibility === 'public',
            // Phase 04 serves public documentation only (§17). The reader-policy
            // input arrives with EffectiveAccess in Phase 21; it is a parameter
            // now so the shape is right before anything serves.
            rulePubliclyCacheable: true,
            cacheTags: CachePolicy::tagsFor(
                mountId: Uuid::toText($mount->id),
                projectId: Uuid::toText($mount->project->id),
                versionId: Uuid::toText($version->id),
                buildId: $match->buildId,
            ),
        );

        if ($this->matchesEtag($request, $etag)) {
            return response('', 304, $directives->headers() + [
                'ETag' => $etag,
                RejectNonCanonicalPath::RESOLVER_HEADER => 'file.not_modified',
            ]);
        }

        return $this->handoff->respond($storageKey, $directives->headers() + $this->contentHeaders(
            path: $file->key,
            contentType: $entry['content_type'],
            etag: $etag,
            indexable: $mount->isIndexable,
        ) + [
            RejectNonCanonicalPath::RESOLVER_HEADER => $route->matchedRule,
        ]);
    }

    /**
     * §8.9.11's type and disposition, plus the headers that are always on.
     *
     * @return array<string, string>
     */
    private function contentHeaders(string $path, string $contentType, string $etag, bool $indexable): array
    {
        $headers = [
            'Content-Type' => $contentType,

            /*
             * 🛑 §8.9.11: "`X-Content-Type-Options: nosniff` **always**". Not
             * conditional on the type being known, because the risk is the
             * browser disagreeing with a type that IS known — an image served
             * as `image/png` whose bytes begin with `<script>` is the case
             * sniffing was invented for and `nosniff` is what refuses it.
             */
            'X-Content-Type-Options' => 'nosniff',
            'ETag' => $etag,
        ];

        /*
         * §8.9.11: "`Content-Disposition: attachment` for anything unknown."
         * `nosniff` stops a browser guessing a type; `attachment` stops it
         * rendering what it was told is opaque bytes. Either alone leaves a
         * case open, which is why §8.9.11 asks for both.
         */
        $headers['Content-Disposition'] = ContentTypes::isKnownPath($path) ? 'inline' : 'attachment';

        /*
         * §8.10.2: `is_indexable` is derived from `mode = 'canonical'`, so a
         * serving alias is `noindex` and the canonical mount is not. Emitted
         * from the mount's own column rather than recomputed, so the header and
         * the database cannot disagree.
         */
        if (! $indexable) {
            $headers['X-Robots-Tag'] = 'noindex';
        }

        return $headers;
    }

    /**
     * Whether `If-None-Match` matches, per RFC 9110's weak comparison rules.
     *
     * 🛑 Compared against the whole header rather than parsed loosely: a client
     * may send several ETags, and `*` means "any representation". Getting this
     * wrong in the permissive direction serves a 304 for content the reader does
     * not have — a blank page they cannot refresh away.
     */
    private function matchesEtag(Request $request, string $etag): bool
    {
        $header = $request->headers->get('If-None-Match');

        if (! is_string($header) || $header === '') {
            return false;
        }

        if (trim($header) === '*') {
            return true;
        }

        foreach (explode(',', $header) as $candidate) {
            $candidate = trim($candidate);

            // A weak validator is `W/"..."`. Our ETags are strong, so a weak
            // one from a client is compared on its opaque part.
            if (str_starts_with($candidate, 'W/')) {
                $candidate = substr($candidate, 2);
            }

            if ($candidate === $etag) {
                return true;
            }
        }

        return false;
    }

    /** §8.9.7's 302. Never cached: the target depends on a pointer that moves. */
    private function redirect(string $to, string $rule): Response
    {
        return response('', 302, [
            'Location' => $to,
            RejectNonCanonicalPath::RESOLVER_HEADER => $rule,

            /*
             * 🛑 `no-store`, not a short max-age. The empty-path redirect points
             * at the default version, and §8.6.14 lets an operator or an
             * automation rule re-point it. A cached redirect would send readers
             * to a version that is no longer default for as long as the cache
             * lived — and §9.3's DDoS runbook names the uncached-302 pattern,
             * so this is a deliberate trade recorded in both directions.
             */
            'Cache-Control' => 'private, no-store',
            'CDN-Cache-Control' => 'private, no-store',
        ]);
    }

    /**
     * A refusal, as cheaply as possible.
     *
     * 🛑 No body, and `no-store`. §9.3.5 names "404 bursts" as a rate-limited
     * class and the DDoS runbook references "the uncached-404/302/search
     * pattern" — so this path has to be the cheapest thing the application can
     * do. A rendered 404 page with a layout and translations would make the
     * cheapest request to generate the most expensive to answer.
     *
     * §8.11.5's 404 chain — suggestions, cross-version existence — arrives with
     * redirects in a later phase and reads the same manifest this method
     * already has. Noted so the absence is visibly deliberate.
     */
    private function refuse(RejectionReason $reason, string $rule): Response
    {
        return response('', $reason->status(), [
            RejectNonCanonicalPath::RESOLVER_HEADER => $rule.':'.$reason->value,
            'Cache-Control' => 'private, no-store',
            'CDN-Cache-Control' => 'private, no-store',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }
}
