<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Serving;

use App\Access\AccessDecision;
use App\Access\AccessSurface;
use App\Access\ReaderGate;
use App\Artifacts\ContentTypes;
use App\Auth\AccessLevel;
use App\Auth\Providers\DegradedResponse;
use App\Http\Middleware\RejectNonCanonicalPath;
use App\Readers\ReaderResolver;
use App\Redirects\RedirectEngine;
use App\Redirects\Redirects;
use App\Redirects\RedirectSet;
use App\Redirects\RedirectTarget;
use App\Serving\ArtifactHandoff;
use App\Serving\CachePolicy;
use App\Serving\CanonicalLocations;
use App\Serving\FileKind;
use App\Serving\Hreflang;
use App\Serving\ManifestReader;
use App\Serving\MountMatch;
use App\Serving\Negotiation;
use App\Serving\NotFoundChain;
use App\Serving\RejectionReason;
use App\Serving\Resolver;
use App\Serving\RouteKind;
use App\Serving\RoutingSnapshotLoader;
use App\Serving\SnapshotMount;
use App\Serving\SnapshotVersion;
use App\Serving\TranslationNotice;
use App\Serving\Translations;
use App\Serving\VersionUrl;
use App\Support\Uuid;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Cookie;
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
 * 4. 🛑 Authorise, through the one `EffectiveAccess` function (§12.3), at
 *    §8.11.1's position: after version resolution and **before** the forced
 *    redirect pass. A forced rule is a redirect to somewhere else on the site,
 *    and emitting one for a reader who may not read this version would disclose
 *    that the version exists.
 * 5. Read the version manifest and the matched build's file manifest, both
 *    immutable and both cached (§8.8.3, §8.4.18).
 * 6. Answer `304` from the manifest digest **before any handoff** (§8.9.9).
 * 7. Decide cacheability through the single three-way check (§9.3.2), with the
 *    authorisation decision supplying its third input.
 * 8. 🛑 Re-check §8.7.7's component ceiling after the mount has matched, and
 *    hand off.
 *
 * Step 6 before step 8 is the one that saves the most work: a repeat reader
 * gets a 304 without the edge touching storage at all.
 *
 * 🛑 Step 4 runs for a **public** project too. §8.12.14: "There MUST be no
 * public fast path that bypasses an authorisation decision on a cached
 * `is_public` flag." The decision is pure and the policy is one cached query,
 * so the public path and the private path are the same path.
 */
final class DocumentController
{
    /**
     * Where §8.6.13's banner is carried.
     *
     * 🛑 The `X-DocUp-` prefix is the family §7.4 strips from every inbound
     * request before Laravel sees it, so a reader cannot send this header and
     * nothing downstream can mistake theirs for ours. §8.15's addons runtime
     * reads it in Phase 28; until then it is what makes the refusal visible
     * from outside, which is the only way §8.6.13 can be checked in
     * production.
     */
    public const NOTICE_HEADER = 'X-DocUp-Notice';

    public function __construct(
        private readonly RoutingSnapshotLoader $snapshots,
        private readonly Resolver $resolver,
        private readonly ManifestReader $manifests,
        private readonly ArtifactHandoff $handoff,
        private readonly Translations $translations,
        private readonly CanonicalLocations $canonical,
        private readonly Redirects $redirects,
        private readonly RedirectEngine $engine,
        private readonly ReaderGate $gate,
        private readonly ReaderResolver $readers,
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
            /*
             * 🛑 §8.6.13's first case: the language itself is absent. The
             * banner is built before the generic refusal, because the
             * refusal's whole virtue is that it is cheap and adding a branch
             * inside it would make every 404 pay for this one.
             */
            if ($route->reason === RejectionReason::LanguageNotFound && $route->mount !== null) {
                return $this->refuseUntranslated(
                    $this->languageAbsentNotice($route->mount, $route->language),
                    $route->matchedRule,
                );
            }

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

        $relative = VersionUrl::within($mount, $path);

        /*
         * 🛑 §12.3's one decision, at §8.11.1's position in the order: after
         * version resolution, before the forced redirect pass.
         *
         * The component ceiling is **not** supplied yet — §8.7.7 requires it to
         * be "re-evaluated on every request after mount matching", and the
         * mount has not matched. It is re-checked below, once it has, and that
         * second call is the requirement rather than a belt-and-braces repeat.
         *
         * 🛑 **`$route->remainder`, not `$relative`**, and the two are
         * different coordinate spaces rather than the same one spelled twice.
         * `$relative` is version-**rooted** — `/en/latest/guide.html` — which
         * is what §8.11.2's redirect patterns are written against, as the
         * twelve documented URL cases show. §12.3 makes an access rule's
         * `path_patterns` "expressed **relative to a component mount**", and
         * `remainder` is exactly that space: the path the resolver matches
         * mount prefixes against. Handing the policy the version-rooted form
         * would make an operator's `/internal` rule match nothing at all —
         * silently, with the section they meant to protect governed by
         * whatever rule comes next.
         */
        /*
         * 🛑 Phase 22's one change to this sequence: the reader is **established
         * before** the decision and the decision is unchanged.
         *
         * {@see ReaderContext}'s Phase 21 comment promised exactly this —
         * "Phase 22 fills it from `docs_sessions` and a verified grant" — and
         * the shape of that promise is what makes this a two-line change rather
         * than a rewrite: `EffectiveAccess` gains no parameter, no branch and no
         * knowledge that sessions exist.
         *
         * 🛑 §8.12.14 still holds. A reader arriving with a valid grant skips
         * the *session lookup*, never the decision: flip this project to private
         * and the next request's grant still verifies and is still refused,
         * because the epoch it carries no longer matches.
         */
        $reader = $this->readers->establish(
            $request,
            $snapshot->domainId,
            $mount->project,
            AccessSurface::Proxy,
        );

        /*
         * 🛑 §8.12.19's branded 503, **before** the decision and not instead of
         * it being made.
         *
         * "A degraded binding MUST deny with a branded 503 naming the binding …
         * never fall back to another provider, never to public." The reader was
         * established as anonymous by the resolver precisely so that nothing
         * downstream can mistake a degraded provider for an absent one — and
         * returning here is what stops a `members` project with a broken IdP
         * answering a 404 that reads as "no such page".
         *
         * 🛑 This is not a path that bypasses §12.3. The refusal has already
         * been reached: {@see \App\Auth\Providers\ProviderOutcome::merge()}
         * short-circuits on `degraded` and establishes no leaves, so §12.3
         * would refuse this reader too. What the 503 changes is the
         * **representation** — §8.12.24's own division between an outcome and
         * how it is rendered.
         */
        if ($reader->isDegraded()) {
            return DegradedResponse::for((string) $reader->degradedBinding);
        }

        $decision = $this->gate->authorise(
            mount: $mount,
            version: $version,
            language: $route->language,
            path: $route->remainder,
            surface: AccessSurface::Proxy,
            reader: $reader->context,
        );

        if (! $decision->allowed) {
            return $this->refuseAccess($decision, $mount, $version);
        }

        /*
         * 🛑 §8.11.1's **forced** user rules, which come after authorisation
         * and before everything that looks at what exists.
         *
         * "Forced" is the whole distinction: this pass wins over a file
         * that is still in the build output, which is how an operator
         * retires a page they cannot remove from the generator. The
         * unforced pass runs after the existence probe, further down, and
         * only catches paths that name nothing.
         */
        $rules = $this->redirects->setFor((string) $mount->project->id, $mount->project->routingEpoch);

        $forced = $this->engine->follow(
            $rules,
            $relative,
            $route->language,
            $version->slug,
            forced: true,
        );

        if ($forced !== null) {
            return $this->redirect(
                $this->absoluteTarget($mount, $forced->to),
                'redirect.'.$forced->rule,
                $forced->status,
            );
        }

        /*
         * 🛑 §8.7.15's generated redirects, consulted BEFORE the mount is
         * matched, and §8.11.1's fixed order is why: "implicit redirects"
         * come before the "existence probe". A shadowed path is one the
         * deeper mount does not serve — the planner only records those —
         * so this can never shadow a real page, and consulting it after the
         * file lookup would turn a redirect into a 404 for every reader
         * whose bookmark the override was meant to protect.
         */
        $shadow = $this->manifests->shadowRedirects($version->publishedManifestId)[$route->remainder] ?? null;

        if (is_string($shadow)) {
            return $this->redirect(
                substr($path, 0, strlen($path) - strlen($route->remainder)).$shadow,
                'composition.shadowed_path',
            );
        }

        $mounts = $this->manifests->mounts($version->publishedManifestId);
        $match = $this->resolver->resolveMount($mounts, $route->remainder);

        if ($match === null || $match->buildId === null) {
            return $this->unforcedOrRefuse(
                $rules,
                $mount,
                $relative,
                $route->language,
                $version->slug,
                RejectionReason::MountNotFound,
                'component.no_match',
                $version,
            );
        }

        /*
         * 🛑 §8.7.7's ceiling, "**re-evaluated on every request after mount
         * matching**" — which is this call and could not have been the one
         * above, because until the mount matched there was no component to ask
         * about.
         *
         * The requirement's reason: without it "any project admin in the
         * organisation can mount any component onto a public project — a
         * declassification primitive in a product whose headline feature is
         * per-project authentication". The snapshot in the manifest is what is
         * consulted rather than the component's current value, so loosening a
         * ceiling cannot retroactively expose what was mounted under the old
         * one; §8.7.7 makes that loosening "a separate audited action that
         * re-validates every existing mount".
         */
        $ceiling = self::componentCeiling($mounts, $match->mountPath);

        if ($ceiling !== null) {
            $decision = $this->gate->authorise(
                mount: $mount,
                version: $version,
                language: $route->language,
                path: $route->remainder,
                surface: AccessSurface::Proxy,
                componentMinAccess: $ceiling,
                reader: $reader->context,
            );

            if (! $decision->allowed) {
                return $this->refuseAccess($decision, $mount, $version);
            }
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
            /*
             * 🛑 §8.6.13's second case, and the one the requirement is
             * actually about: the language exists, this page is not in it.
             * "never a silent fallback to another language" — so the answer
             * is still a 404 and the only thing that changes is that the
             * reader is told where the page does live.
             */
            $notice = $this->untranslatedNotice($mount, $version, $route->remainder);

            if ($notice !== null) {
                return $this->refuseUntranslated($notice, 'file.no_match');
            }

            /*
             * 🛑 §8.11.1's last step: "**unforced** user rules by position",
             * after the existence probe has shown the path names nothing.
             * This is the ordinary case — an inbound link to a page that was
             * removed — and running it here rather than earlier is what
             * stops a widened pattern from shadowing a live page.
             */
            return $this->unforcedOrRefuse(
                $rules,
                $mount,
                $relative,
                $route->language,
                $version->slug,
                $file->reason ?? RejectionReason::FileNotFound,
                'file.no_match',
                $version,
            );
        }

        $entry = $file->entry;

        if ($file->key === null || $file->etag() === null || $entry === null) {
            return $this->refuse(RejectionReason::FileNotFound, 'file.no_storage_key');
        }

        /*
         * §8.9.13: serve a pre-compressed sidecar where one exists. The chosen
         * key may therefore differ from the resolved one — and when it does, the
         * ETag comes from the SIDECAR's manifest entry, because §8.9.12 derives
         * the validator from the digest of what is served. A shared validator
         * would let a cache answer a client that never asked for gzip.
         */
        $files = $this->manifests->files($match->buildId);

        [$servedKey, $encoding] = Negotiation::choose(
            $files,
            $file->key,
            $request->headers->get('Accept-Encoding'),
        );

        $servedEntry = $files[$servedKey] ?? $entry;

        // §8.8.1's prefix is built by the artifact store and nowhere else; the
        // manifest path is the rest of the key.
        $storageKey = $this->manifests->storageKeyFor($match->buildId, $servedKey);

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
            /*
             * 🛑 §9.3.2's third input, now supplied by the decision rather than
             * assumed. Phase 04 left this `true` with a note saying the reader
             * policy would fill it in Phase 21; this is that.
             *
             * It can only narrow. A rule may declare itself publicly cacheable
             * only when its requirement is literally the public terminal
             * (refused at write time otherwise), so an allow that needed a
             * credential arrives here as `false` and the response is private —
             * which is the direction §9.3.2 cares about.
             */
            rulePubliclyCacheable: $decision->rulePubliclyCacheable,
            cacheTags: CachePolicy::tagsFor(
                mountId: Uuid::toText($mount->id),
                projectId: Uuid::toText($mount->project->id),
                versionId: Uuid::toText($version->id),
                buildId: $match->buildId,
            ),
        );

        /*
         * The validator describes the bytes that will be sent, so it is taken
         * after negotiation. §8.9.12: "an `ETag` derived from the manifest
         * digest" — of the served object.
         */
        $etag = '"'.$servedEntry['sha256'].'"';

        /*
         * 🛑 §8.12.11's grant, minted once per TTL and **after** the allow.
         *
         * Attached to the 304 as well as the 200, because a conditional request
         * is a request: a reader whose grant expired while their browser held a
         * fresh `If-None-Match` would otherwise get a 304 with no new grant,
         * and every subsequent asset would re-read the session. One place,
         * both exits.
         */
        $issued = $snapshot->domainId === null ? [] : $this->readers->issue(
            decision: $decision,
            reader: $reader,
            project: $mount->project,
            domainId: $snapshot->domainId,
            versionId: $version->id,
            versionSlug: $version->slug,
            surface: AccessSurface::Proxy,
        );

        if ($this->matchesEtag($request, $etag)) {
            return self::withCookies(
                response('', 304, $directives->headers() + ReaderGate::headers($decision) + [
                    'ETag' => $etag,
                    RejectNonCanonicalPath::RESOLVER_HEADER => 'file.not_modified',
                ]),
                $issued,
            );
        }

        $headers = $directives->headers() + ReaderGate::headers($decision) + $this->contentHeaders(
            // The RESOLVED path, not the served one: the content type and the
            // inline/attachment disposition describe the document a reader
            // asked for, not the container it arrived in. A gzip sidecar of an
            // HTML page is still `text/html`.
            path: $file->key,
            contentType: $entry['content_type'],
            etag: $etag,
            indexable: $mount->isIndexable,
        ) + [
            RejectNonCanonicalPath::RESOLVER_HEADER => $route->matchedRule,
        ];

        if ($encoding !== null) {
            $headers['Content-Encoding'] = $encoding;
        }

        /*
         * 🛑 §8.11.9's `rel=canonical` and §8.11.6's `hreflang`, in one
         * `Link` header because RFC 8288 makes it one field.
         *
         * Both are headers rather than DOM edits for the same reason:
         * nothing rewrites documentation on the serving path (§4.3/6,
         * §8.9.8). And both exist to answer the same question for a crawler
         * — §8.10.2 makes **every** verified domain answer 200 rather than
         * redirect, which is what makes G6 real, and the only thing then
         * keeping N hostnames from looking like N copies of a site is this
         * header.
         */
        $links = array_filter([
            $this->canonicalLink($mount, $version, $route->remainder, $file->key),
            Hreflang::header($this->alternatesFor($mount, $version, $route->remainder, $file->key)),
        ], is_string(...));

        if ($links !== []) {
            $headers['Link'] = implode(', ', $links);
        }

        return self::withCookies($this->handoff->respond($storageKey, $headers), $issued);
    }

    /**
     * Attach §12.4's cookies to a response.
     *
     * 🛑 A helper rather than two call sites, because the 200 and the 304 must
     * carry the same `Set-Cookie` headers and the one that gets forgotten is
     * always the 304 — it is the exit nobody tests by hand.
     *
     * @param  list<Cookie>  $cookies
     */
    private static function withCookies(Response $response, array $cookies): Response
    {
        foreach ($cookies as $cookie) {
            $response->headers->setCookie($cookie);
        }

        return $response;
    }

    /**
     * 🛑 §8.11.9: "`rel=canonical` MUST be emitted as an HTTP `Link` header …
     * For N domains serving identical content, canonical MUST always point at
     * the project's canonical mount."
     *
     * Emitted on HTML only. A stylesheet has no canonical URL, and annotating
     * one would be noise on every asset of every page.
     *
     * Returns null when the project has no canonical mount or that mount's
     * host cannot serve: §8.10.3 puts exactly one canonical mount behind a
     * unique index, and a canonical link pointing at a host that serves
     * nothing is worse than none — a crawler drops the page that does work in
     * favour of one that does not.
     */
    private function canonicalLink(
        SnapshotMount $mount,
        SnapshotVersion $version,
        string $within,
        string $resolvedKey,
    ): ?string {
        if (! str_ends_with($resolvedKey, '.html')) {
            return null;
        }

        $location = $this->canonical->for($mount->project->id, $mount->project->routingEpoch);

        if ($location === null) {
            return null;
        }

        $url = $location->origin.VersionUrl::document(
            $location->mountFor($mount->project),
            $mount->versioningScheme(),
            $version,
            $within,
        );

        return '<'.$url.'>; rel="canonical"';
    }

    /**
     * §8.11.6's alternate set for the document being served.
     *
     * 🛑 **Gated three ways, and each gate is a cost argument.** Most
     * projects have one language, so the common path must not pay for this
     * at all: a project whose scheme carries no language in the URL has no
     * alternates by construction; a version with no `translation_group_id`
     * is not a translation of anything (§8.6.12); and a stylesheet is not a
     * page. Only past all three does this read a sibling's file manifest —
     * one cached read per language, on an HTML response.
     *
     * @return list<array{hreflang: string, href: string}>
     */
    private function alternatesFor(
        SnapshotMount $mount,
        SnapshotVersion $version,
        string $within,
        string $resolvedKey,
    ): array {
        if ($mount->versioningScheme() !== 'lang_and_version' || $version->translationGroupId === null) {
            return [];
        }

        if (! str_ends_with($resolvedKey, '.html')) {
            return [];
        }

        $location = $this->canonical->for($mount->project->id, $mount->project->routingEpoch);

        if ($location === null) {
            // §8.10.3's canonical mount is gone or cannot serve. An alternate
            // set anchored on a host that serves nothing is worse than none.
            return [];
        }

        return Hreflang::alternates(
            $this->translations->pagesFor($mount->project, $version, $within, $location),
            $location->origin,
            $mount->project->defaultVersion()?->language,
        );
    }

    /**
     * 🛑 §8.6.13's banner for a page that exists in another language.
     *
     * Returns null when there is nothing to say — an ungrouped version, a
     * page that exists nowhere, or a project with one language — and the
     * caller then answers with the ordinary cheap 404. The banner is for the
     * case where a fallback would have been *tempting*, which is exactly the
     * case §8.6.13 forbids.
     */
    private function untranslatedNotice(
        SnapshotMount $mount,
        SnapshotVersion $version,
        string $within,
    ): ?TranslationNotice {
        if ($mount->versioningScheme() !== 'lang_and_version' || $version->translationGroupId === null) {
            return null;
        }

        $location = $this->canonical->for($mount->project->id, $mount->project->routingEpoch);

        if ($location === null) {
            return null;
        }

        $elsewhere = [];

        foreach ($this->translations->pagesFor($mount->project, $version, $within, $location) as $page) {
            if ($page['language'] === $version->language) {
                /*
                 * The page exists in the language being served, yet the file
                 * lookup missed. That is a disagreement between two readings
                 * of one manifest, not a translation gap, and reporting it as
                 * one would hide it — so this falls through to the plain 404.
                 */
                return null;
            }

            $elsewhere[] = ['language' => $page['language'], 'href' => $location->origin.$page['path']];
        }

        return $elsewhere === []
            ? null
            : new TranslationNotice(TranslationNotice::PAGE_UNTRANSLATED, $version->language, $elsewhere);
    }

    /** §8.6.13's banner for a language the project does not publish at all. */
    private function languageAbsentNotice(SnapshotMount $mount, string $language): TranslationNotice
    {
        $location = $this->canonical->for($mount->project->id, $mount->project->routingEpoch);

        return new TranslationNotice(
            TranslationNotice::LANGUAGE_ABSENT,
            $language,
            $location === null ? [] : $this->translations->languageRoots($mount->project, $location),
        );
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
    private function redirect(string $to, string $rule, int $status = 302): Response
    {
        return response('', $status, [
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
     * §8.11.1's last step, then §8.11.5's chain.
     *
     * One method because they are one decision: either an unforced rule
     * catches the path, or nothing does and the chain decides what the
     * reader sees instead.
     */
    private function unforcedOrRefuse(
        RedirectSet $rules,
        SnapshotMount $mount,
        string $relative,
        string $language,
        string $versionSlug,
        RejectionReason $reason,
        string $rule,
        ?SnapshotVersion $version = null,
    ): Response {
        $match = $this->engine->follow($rules, $relative, $language, $versionSlug, forced: false);

        if ($match !== null) {
            return $this->redirect(
                $this->absoluteTarget($mount, $match->to),
                'redirect.'.$match->rule,
                $match->status,
            );
        }

        return $this->refuse($reason, $rule, $mount, $version);
    }

    /**
     * A rule's root-relative target, put back into the mount's URL space.
     *
     * {@see VersionUrl::within()} is what took the prefixes off, so this
     * is its inverse and they move together.
     */
    private function absoluteTarget(SnapshotMount $mount, string $target): string
    {
        if (RedirectTarget::isAbsolute($target)) {
            return $target;
        }

        return VersionUrl::shed($mount).$target;
    }

    /**
     * A refusal, as cheaply as possible — and, since §8.11.8, one the edge
     * may keep.
     *
     * 🛑 **Edge-cacheable where it is safe, and `private, no-store` where it
     * is not.** §8.11.8 wants a 404 the edge can absorb; §9.3.2 forbids a
     * public directive on anything private. Those are not in tension for a
     * genuine absence and are in direct conflict for a 404 that §12 is
     * using to hide something, so the choice is delegated to
     * {@see CachePolicy::forAbsence()} — the one place §9.3.2's
     * architecture test permits a public decision to be made.
     *
     * 🛑 Still no body for anything but a document request. §9.3.5 names
     * "404 bursts" as a rate-limited class, so this is the response a flood
     * receives and it has to stay the cheapest thing the application can
     * produce. §8.11.5's branded page is bytes from a constant, which is
     * cheap; a rendered page with a layout and translations would not be.
     */
    private function refuse(
        RejectionReason $reason,
        string $rule,
        ?SnapshotMount $mount = null,
        ?SnapshotVersion $version = null,
    ): Response {
        $directives = CachePolicy::forAbsence(
            projectIsPublic: $mount === null ? null : $mount->project->visibility === 'public',
            versionIsPublic: $version === null ? null : $version->visibility === 'public',
        );

        $headers = [
            RejectNonCanonicalPath::RESOLVER_HEADER => $rule.':'.$reason->value,
            'X-Content-Type-Options' => 'nosniff',
            ...$directives->headers(),
        ];

        if ($reason->status() !== 404) {
            return response('', $reason->status(), $headers);
        }

        /*
         * 🛑 §8.11.5's last link, and ADR 0003's reason for skipping the
         * one before it. A build's own `404.html` is served only when the
         * ingestor saw no root-absolute references in it, or when this
         * mount is at the origin root where those references resolve —
         * otherwise the reader gets DocUp's page rather than a
         * stylesheet-less copy of the project's.
         *
         * The build page itself is handed off by the edge in a later
         * phase; what is implemented here is the decision and the
         * fallback, which is the half that can be wrong silently.
         */
        return response(NotFoundChain::builtIn(), 404, [
            ...$headers,
            'Content-Type' => 'text/html; charset=utf-8',
        ]);
    }

    /**
     * 🛑 §8.12.23's refusal, with the status the decision already chose.
     *
     * > "The denial outcome is decided by the request's **authorisation
     * > state**, never by its `Accept` or `Sec-Fetch-*` headers; those choose
     * > only the *representation* of an already-decided outcome (§8.12.24)."
     *
     * So this method chooses no status. {@see AccessDecision::$status} is
     * already 404, 403, 401 or 503 and this is where that number becomes a
     * response — which is the whole reason the status lives on the decision
     * rather than being computed by each of the four surfaces.
     *
     * 🛑 **Private cache directives, always.** §9.3.2 and the §17 exit
     * criterion both: a refusal about something private "carries private cache
     * directives on both axes with no cache tag".
     * {@see CachePolicy::forAbsence()} already makes that decision from the
     * project and version, and the third argument is the decision's — a 404
     * that §12 used to hide something is never publicly cacheable, however
     * cacheable an ordinary 404 is (§8.11.8).
     */
    private function refuseAccess(
        AccessDecision $decision,
        SnapshotMount $mount,
        SnapshotVersion $version,
    ): Response {
        $directives = CachePolicy::forAbsence(
            projectIsPublic: $mount->project->visibility === 'public',
            versionIsPublic: $version->visibility === 'public',
            rulePubliclyCacheable: $decision->rulePubliclyCacheable,
        );

        $headers = [
            RejectNonCanonicalPath::RESOLVER_HEADER => 'access.'.$decision->reason->value,
            'X-Content-Type-Options' => 'nosniff',
            ...$directives->headers(),
            ...ReaderGate::headers($decision),
        ];

        /*
         * 🛑 An **empty** body for everything that is not a plain 404.
         *
         * §8.12.24: "Where §8.12.23 does **not** permit a challenge, both
         * client classes receive the same `deny_status` and the same empty
         * body." A 401 and a 403 therefore carry nothing — and the branded 404
         * page is served only where the answer is indistinguishable from
         * absence, which is the one case where a page is not a disclosure.
         */
        if ($decision->status !== 404) {
            return response('', $decision->status, $headers);
        }

        return response(NotFoundChain::builtIn(), 404, [
            ...$headers,
            'Content-Type' => 'text/html; charset=utf-8',
        ]);
    }

    /**
     * §8.7.7's snapshotted ceiling for the matched mount, or null.
     *
     * Read from the manifest's own mount row rather than from
     * {@see MountMatch}, which carries the mount path and the
     * build id and is **frozen** by §17.4. A field on a frozen value object is
     * an ADR; a lookup in the array the caller already holds is not, and the
     * two are indistinguishable from the outside.
     *
     * @param  list<array{mount_path: string, build_id: string|null, min_access?: string}>  $mounts
     */
    private static function componentCeiling(array $mounts, string $mountPath): ?AccessLevel
    {
        foreach ($mounts as $row) {
            if ($row['mount_path'] === $mountPath) {
                return AccessLevel::tryFrom($row['min_access'] ?? '');
            }
        }

        return null;
    }

    /**
     * 🛑 §8.6.13: "404 plus a notification banner, never a silent fallback".
     *
     * Still a 404 — the status is the requirement and the banner is the
     * courtesy. The body is the one exception to {@see self::refuse()}'s
     * empty-body rule and it is a few hundred static bytes, because a reader
     * who followed a link into an untranslated page otherwise sees a blank
     * page and has no way to learn that the English one exists.
     *
     * 🛑 **No `Vary: Accept-Language`.** §8.6.13 is explicit that locale
     * negotiation is URL-only, and the header "would destroy edge
     * cacheability" — the language came from the path, so the response does
     * not vary on anything the reader sent.
     */
    private function refuseUntranslated(TranslationNotice $notice, string $rule): Response
    {
        return response($notice->body(), 404, [
            RejectNonCanonicalPath::RESOLVER_HEADER => $rule.':'.RejectionReason::FileNotFound->value,
            self::NOTICE_HEADER => $notice->header(),
            'Content-Type' => 'text/html; charset=utf-8',
            'Cache-Control' => 'private, no-store',
            'CDN-Cache-Control' => 'private, no-store',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }
}
