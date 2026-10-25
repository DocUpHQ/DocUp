<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Serving;

use App\Http\Controllers\Controller;
use App\Http\Middleware\RejectNonCanonicalPath;
use App\Serving\ArtifactHandoff;
use App\Serving\CachePolicy;
use App\Serving\ManifestReader;
use App\Serving\OfflineFormat;
use App\Serving\RejectionReason;
use App\Serving\RoutingSnapshotLoader;
use App\Serving\SnapshotProject;
use App\Serving\SnapshotVersion;
use App\Support\Uuid;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * §7.3's `/_/downloads/...` — the offline formats (§8.4.5).
 *
 * The URL is `/_/downloads/{language}/{version}/{format}`, which is Read the
 * Docs' own shape and is deliberate: §3 and §20.4 make RTD compatibility a
 * goal, and a migrating project's README links and its users' bookmarks both
 * point at that path. 🛑 It carries the language and the version **whatever
 * the project's §8.6.9 versioning scheme is**, including `single_version`,
 * where documentation URLs carry neither. A scheme-dependent download URL
 * would change when an operator changed the scheme, which is the one thing a
 * bookmarked link must survive.
 *
 * 🛑 **The stored object's path contains no slug and the download's filename
 * is nothing but slugs.** §8.4.5 asks for exactly that split: the object is
 * `builds/<uuid>/pdf/document.pdf`, and `Content-Disposition` names it
 * `<project>-<version>.pdf` at serve time. A project renamed tomorrow keeps
 * every stored byte and changes every filename, with no rebuild.
 *
 * 🛑 **An HTML file renamed `.pdf` must not run.** The bytes behind
 * `pdf/document.pdf` are whatever the build wrote; DocUp controls the path
 * and the headers, never the content. Four controls together, each doing
 * something the others do not — see {@see downloadHeaders()}.
 */
final class DownloadController extends Controller
{
    public function __construct(
        private readonly RoutingSnapshotLoader $snapshots,
        private readonly ManifestReader $manifests,
        private readonly ArtifactHandoff $handoff,
    ) {}

    /**
     * 🛑 `$docupHostLabel` is the DOMAIN parameter and Laravel passes it
     * first, before every path parameter.
     *
     * It is named and ignored rather than omitted, because omitting it
     * shifts every other argument by one: the controller is handed the host
     * label as `$language`, the language as `$version` and the version as
     * `$format` — and `OfflineFormat::tryFrom()` then refuses a perfectly
     * good request with `download.unknown_format`, which reads like a reader
     * error rather than a wiring one. Found exactly that way.
     *
     * The value is never read, and must not be: §8.9.4 forbids resolving a
     * project from anything but the host and the path, and the snapshot
     * loader already takes the whole host. A controller reading this would
     * be a second source of truth for the tenant.
     */
    public function __invoke(
        Request $request,
        string $docupHostLabel,
        string $language,
        string $version,
        string $format,
    ): Response {
        $snapshot = $this->snapshots->load((string) $request->getHost());

        if (! $snapshot->servable) {
            return $this->refuse(RejectionReason::HostNotFound, 'download.host_not_found');
        }

        /*
         * 🛑 The format is reader input and it decides a storage path, so it
         * is matched against the enum rather than interpolated. `tryFrom`
         * returning null is a 404: a reader asking for `../../etc` gets the
         * same answer as one asking for `mobi`, and neither reaches the
         * manifest.
         */
        $offline = OfflineFormat::tryFrom($format);

        if ($offline === null) {
            return $this->refuse(RejectionReason::FileNotFound, 'download.unknown_format');
        }

        /*
         * One domain mount per download host is the shape Phase 04 built and
         * Phase 13 generalises. The empty prefix is the project at the host
         * root, which is every project until a path-prefixed mount exists.
         */
        $mountMatch = $snapshot->matchFor('/');

        if ($mountMatch === null) {
            return $this->refuse(RejectionReason::MountNotFound, 'download.no_domain_mount');
        }

        $project = $mountMatch->mount->project;
        $resolved = $this->versionFor($project, $language, $version);

        if ($resolved === null || ! $resolved->isServable()) {
            return $this->refuse(RejectionReason::NothingPublished, 'download.version_not_servable');
        }

        /*
         * 🛑 §8.7.19: "only the **primary** component mount MAY emit `pdf`,
         * `epub` and `htmlzip`." Until Phase 13 a version has one mount and it
         * is the primary one, but reading `is_primary` rather than taking the
         * first entry is what makes the rule hold when that stops being true —
         * and §8.7.19 exists precisely so the ambiguity "cannot recur".
         */
        $buildId = $this->primaryBuildFor((string) $resolved->publishedManifestId);

        if ($buildId === null) {
            return $this->refuse(RejectionReason::MountNotFound, 'download.no_primary_mount');
        }

        $files = $this->manifests->files($buildId);
        $manifestPath = $offline->manifestPath();
        $entry = $files[$manifestPath] ?? null;

        if ($entry === null) {
            /*
             * The version is published and this format is not in it — the
             * ordinary answer for a project that builds HTML only. A 404
             * rather than a 501: the reader asked for a document, and whether
             * one exists is a fact about this version, not about DocUp.
             */
            return $this->refuse(RejectionReason::FileNotFound, 'download.format_not_built');
        }

        $etag = '"'.$entry['sha256'].'"';

        $directives = CachePolicy::decide(
            projectIsPublic: $project->visibility === 'public',
            versionIsPublic: $resolved->visibility === 'public',
            // §12's reader policy reaches this endpoint with EffectiveAccess in
            // Phase 21, exactly as it reaches the document proxy. A parameter
            // now so the shape is right before anything serves.
            rulePubliclyCacheable: true,
            cacheTags: CachePolicy::tagsFor(
                mountId: Uuid::toText($mountMatch->mount->id),
                projectId: Uuid::toText($project->id),
                versionId: Uuid::toText($resolved->id),
                buildId: $buildId,
            ),
        );

        if ($this->matchesEtag($request, $etag)) {
            return response('', 304, $directives->headers() + [
                'ETag' => $etag,
                RejectNonCanonicalPath::RESOLVER_HEADER => 'download.not_modified',
            ]);
        }

        return $this->handoff->respond(
            $this->manifests->storageKeyFor($buildId, $manifestPath),
            $directives->headers() + $this->downloadHeaders($offline, $project, $resolved, $etag),
        );
    }

    /**
     * 🛑 The four controls that make "an HTML file renamed `.pdf`" inert.
     *
     * Phase 12's exit criterion: "An HTML file renamed `.pdf` is served with
     * headers that prevent active content." Each control below closes a case
     * the others leave open, which is why there are four rather than one:
     *
     *   1. **`Content-Type` from the FORMAT**, never from the stored bytes or
     *      from a filename. The object lives at `pdf/document.pdf` because
     *      ingest put it there, so the type is `application/pdf` whatever the
     *      build wrote — which is what makes the remaining three apply.
     *   2. **`X-Content-Type-Options: nosniff`** (§8.9.11). Without it a
     *      browser that sees `<html>` behind `application/pdf` may render it
     *      anyway, which is the whole of the content-sniffing attack.
     *   3. **`Content-Disposition: attachment`**, always, never `inline`. A
     *      download is a download; `nosniff` stops the browser guessing a
     *      type and `attachment` stops it rendering one it was given.
     *   4. **`Content-Security-Policy: sandbox`**. The backstop for the case
     *      the first three miss: a reader who saves the file and opens it, or
     *      a browser extension that renders PDFs in-page. `sandbox` with no
     *      tokens denies scripts, forms, popups and same-origin access — and
     *      a PDF viewer needs none of them, so nothing legitimate is lost.
     *      This matters more than it looks: a PDF is itself a scriptable
     *      format, so the "renamed HTML" case and the "genuinely a PDF" case
     *      want the same answer.
     *
     * @return array<string, string>
     */
    private function downloadHeaders(
        OfflineFormat $format,
        SnapshotProject $project,
        SnapshotVersion $version,
        string $etag,
    ): array {
        return [
            'Content-Type' => $format->contentType(),
            'X-Content-Type-Options' => 'nosniff',
            'Content-Disposition' => $this->disposition($format, $project, $version),
            'Content-Security-Policy' => "default-src 'none'; sandbox",

            /*
             * 🛑 Not indexable, on every download. A search engine indexing a
             * 40 MB PDF of the same content the HTML already carries competes
             * with the canonical pages for the query it should answer — and
             * §8.11's SEO work is about the HTML being the answer.
             */
            'X-Robots-Tag' => 'noindex',
            'ETag' => $etag,
        ];
    }

    /**
     * §8.4.5's `<project>-<version>.<ext>`, as an RFC 6266 header.
     *
     * 🛑 Both the plain `filename` and the extended `filename*` are sent,
     * because the slugs are ASCII by construction (§8.6.6's slug function and
     * the project slug rule) but the header must stay correct if that ever
     * stops being true. The plain form is for the clients that ignore
     * `filename*`; a client honouring both prefers the extended one, per the
     * RFC.
     *
     * 🛑 The value is quoted and the slugs cannot contain a quote, a
     * backslash or a control character — §8.6.6's permitted set is
     * `[a-z0-9._-]`. Said explicitly because a response-header injection
     * through a filename is a real class of bug, and the reason it cannot
     * happen here is the slug function rather than anything in this method.
     */
    private function disposition(OfflineFormat $format, SnapshotProject $project, SnapshotVersion $version): string
    {
        $name = $project->slug.'-'.$version->slug.'.'.$format->extension();

        return 'attachment; filename="'.$name.'"; filename*=UTF-8\'\''.rawurlencode($name);
    }

    /**
     * The version a download URL names, by language and slug.
     *
     * 🛑 No former-slug 301 here, unlike §8.6.6's document path. A download
     * client is `curl` in a script as often as it is a browser, and a 301 on
     * a binary download is followed by some clients and silently dropped by
     * others. The slug history exists and Phase 13 may use it; for now a
     * renamed version's old download URL 404s, which is honest, rather than
     * redirecting into something half of callers will not follow.
     */
    private function versionFor(SnapshotProject $project, string $language, string $slug): ?SnapshotVersion
    {
        return $project->version($language, $slug);
    }

    /**
     * The build behind the primary mount of a published manifest.
     *
     * @param  string  $manifestId  raw 16 bytes, as the snapshot carries it
     */
    private function primaryBuildFor(string $manifestId): ?string
    {
        foreach ($this->manifests->mounts($manifestId) as $mount) {
            if ($mount['is_primary'] === true && $mount['build_id'] !== null) {
                return $mount['build_id'];
            }
        }

        return null;
    }

    /** RFC 9110 weak comparison, as {@see DocumentController} does it. */
    private function matchesEtag(Request $request, string $etag): bool
    {
        $header = $request->headers->get('If-None-Match');

        if ($header === null || $header === '') {
            return false;
        }

        if (trim($header) === '*') {
            return true;
        }

        foreach (explode(',', $header) as $candidate) {
            if (ltrim(trim($candidate), 'W/') === $etag) {
                return true;
            }
        }

        return false;
    }

    private function refuse(RejectionReason $reason, string $rule): Response
    {
        /*
         * 🛑 404 for every refusal, like the document proxy. §8.12.23 makes
         * 404 the default over 403 for the reason it states, and on this
         * endpoint the point is sharper: a 403 for "this version is private"
         * beside a 404 for "no such version" tells an anonymous reader which
         * versions exist.
         */
        return response('', 404, [
            'Cache-Control' => 'no-store',
            'X-Content-Type-Options' => 'nosniff',
            RejectNonCanonicalPath::RESOLVER_HEADER => $rule,
            'X-DocUp-Refusal' => $reason->value,
        ]);
    }
}
