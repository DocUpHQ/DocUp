<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Serving;

use App\Access\AccessSurface;
use App\Access\ReaderContext;
use App\Access\ReaderGate;
use App\Addons\AddonsContext;
use App\Addons\AddonsPayload;
use App\Artifacts\ArtifactIngestor;
use App\Auth\OrganisationContext;
use App\Http\Controllers\Controller;
use App\Http\Controllers\Readers\AuthzController;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Readers\ReaderResolver;
use App\Seo\GeneratedArtifacts;
use App\Serving\CachePolicy;
use App\Serving\CanonicalLocation;
use App\Serving\CanonicalLocations;
use App\Serving\CanonicalPath;
use App\Serving\RejectionReason;
use App\Serving\Resolver;
use App\Serving\RouteKind;
use App\Serving\RouteOutcome;
use App\Serving\RoutingSnapshotLoader;
use App\Serving\SnapshotMount;
use App\Serving\SnapshotVersion;
use App\Serving\TranslationNotice;
use App\Serving\Translations;
use App\Versions\PageExistence;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * 🛑 §8.15.2's `GET /_/addons`.
 *
 * > "All request-scoped data MUST come from `GET /_/addons`, resolved from the
 * > **request's** host and path, authorised identically to the HTML, with
 * > `Vary: Cookie`."
 *
 * Three obligations, and each one is a defect if it is missed.
 *
 * ## 1. Resolved from the request's host and path
 *
 * The host is the request's own. The **path** cannot be: this endpoint's URI is
 * `/_/addons`, and what the runtime needs described is the document it was
 * loaded by. So the document's path arrives as a `path` query parameter — and
 * 🛑 it is treated as reader input from the first line, because it decides which
 * version's data is returned.
 *
 * It is canonicalised through {@see CanonicalPath} and resolved through the one
 * {@see Resolver}, exactly as {@see DocumentController} resolves a document.
 * §8.9.4's rule holds throughout: the project comes from the host and the path
 * and from nothing else, and no request header selects anything.
 *
 * 🛑 This is the same shape as {@see AuthzController},
 * and that controller records the subtlety worth repeating — a parameter that
 * decides an authorisation subject must be unambiguous. Here the value arrives
 * in an ordinary browser query string rather than inside nginx's
 * `$request_uri`, so there is no second `uri=` for a client to smuggle in; the
 * path is still re-canonicalised rather than trusted, because a reader who
 * could get `..` past this would be naming a version the resolver never agreed
 * to.
 *
 * ## 2. Authorised identically to the HTML
 *
 * The same {@see ReaderGate} call the document proxy makes, on the same mount,
 * version, language and remainder, with {@see AccessSurface::Addons}. A refusal
 * carries §8.12.23's status for the project rather than a 403 — §8.2.2's "404,
 * never 403" holds here because the existence of a private version is part of
 * what is being protected.
 *
 * 🛑 **And the flyout is filtered version by version**, because §8.12.9 makes
 * the flyout one of the surfaces that must be "generated from the **authorised**
 * view": a reader who may read `v1` and not `v2` must not learn that `v2`
 * exists. That is one gate call per listed version, which is the cost of the
 * guarantee and is why {@see AddonsContext} is assembled once.
 *
 * ## 3. `Vary: Cookie`
 *
 * Because the answer depends on the reader's grant. Applied through
 * {@see CachePolicy::forAddons()}, which is the only place in the product that
 * decides a cache directive (§9.3.2).
 */
final readonly class AddonsController
{
    /**
     * The longest document path this endpoint will consider.
     *
     * §7.3 paths are already bounded by the ingestor's own 900-byte limit
     * ({@see ArtifactIngestor}); a generous multiple of that is
     * still far below anything that costs time. The cap exists so that a
     * megabyte query string is refused **before** any resolution rather than
     * after — §9.3.5 names 404 bursts as an abuse class, and this endpoint is
     * cheaper to call than a document.
     */
    private const int MAX_PATH_BYTES = 2048;

    public function __construct(
        private RoutingSnapshotLoader $snapshots,
        private Resolver $resolver,
        private ReaderGate $gate,
        private ReaderResolver $readers,
        private AddonsPayload $payload,
        private PageExistence $pages,
        private Translations $translations,
        private CanonicalLocations $canonical,
        private OrganisationContext $organisations,
    ) {}

    public function __invoke(Request $request): Response
    {
        $snapshot = $this->snapshots->load((string) $request->getHost());

        if (! $snapshot->servable || $snapshot->domainId === null || $snapshot->mounts === []) {
            return $this->refuse(404);
        }

        $path = $this->pathFrom($request);

        if ($path === null) {
            return $this->refuse(400, 'addons.path_not_canonical');
        }

        $route = $this->resolver->resolveRoute($snapshot, $path);

        /*
         * The mount from the resolution where there was one, and from the
         * host's own mount table where the path resolved to nothing — a reader
         * on a 404 page still gets chrome, and chrome still needs the project's
         * theme.
         */
        $mount = $route->mount ?? $snapshot->matchFor($path)?->mount;

        if (! $mount instanceof SnapshotMount) {
            return $this->refuse(404);
        }

        /*
         * 🛑 `withoutGlobalScopes`, like every other serving-path read of a
         * project row. §8.2.1's tenant scope comes *from* the hostname here
         * (see {@see RoutingSnapshotLoader}), so a scoped query would have no
         * tenant to scope to and would return nothing.
         */
        $project = Project::withoutGlobalScopes()->whereKey($mount->project->id)->first();

        if (! $project instanceof Project) {
            return $this->refuse(404);
        }

        $reader = $this->readers->establish(
            $request,
            $snapshot->domainId,
            $mount->project,
            AccessSurface::Addons,
        );

        $version = $route->kind === RouteKind::Resolved ? $route->version : null;
        $decisionHeader = 'addons.anonymous';

        if ($version instanceof SnapshotVersion) {
            /*
             * 🛑 §8.15.2's "authorised identically to the HTML": the same gate,
             * the same four inputs, on the same surface the payload is for.
             */
            $decision = $this->gate->authorise(
                mount: $mount,
                version: $version,
                language: $route->language,
                path: $route->remainder,
                surface: AccessSurface::Addons,
                reader: $reader->context,
            );

            if (! $decision->allowed) {
                return $this->refuse($mount->project->denyStatus, 'addons.denied');
            }

            $decisionHeader = $decision->header();
        } elseif (! $this->mayDescribeProject($mount, $reader->context)) {
            return $this->refuse($mount->project->denyStatus, 'addons.denied');
        }

        $rows = $this->authorisedVersions($mount, $reader->context);
        $remainder = $version instanceof SnapshotVersion ? $route->remainder : '';
        $pageExists = $this->pageExistence($rows, $remainder);

        $context = new AddonsContext(
            project: $project,
            mount: $mount,
            version: $version,
            route: $route,
            hostKind: $snapshot->kind,
            rows: $rows,
            pageExists: $pageExists,
            notice: $this->noticeFor($mount, $route, $version, $remainder, $pageExists),
            origin: $request->getSchemeAndHttpHost(),
        );

        /*
         * 🛑 The tenant is DECLARED before the payload is assembled, and the
         * reason is in App\Branding\Themes::forMount(): it reads `DomainMount`
         * through the model so §8.2.1's global scope applies, "so that a mount
         * from another tenant must not contribute a layer". Nothing had
         * resolved a theme on a documentation request before this endpoint, so
         * the serving path had never needed a context — and the symptom of its
         * absence was a 500 on every payload, found by the scope doing exactly
         * what it exists for.
         *
         * Scoped to the organisation the host resolved to, never spanning all
         * of them: the narrower posture is available here because the snapshot
         * already decided the tenant, and §8.9.4 forbids re-deriving it from
         * anything else.
         */
        $body = $this->organisations->withinOrganisation(
            (string) $mount->project->organisationId,
            fn (): array => $this->payload->for($context),
        );

        return new JsonResponse(
            $body,
            200,
            [
                /*
                 * 🛑 §9.3.2 through {@see CachePolicy}, the one place in the
                 * product that decides cacheability — the architecture test
                 * looks there and nowhere else. `forAddons()` is
                 * `private, no-store` with `Vary: Cookie`, which is §8.15.2's
                 * requirement and §7.3's rule for this namespace together.
                 */
                ...CachePolicy::forAddons()->headers(),
                'X-Content-Type-Options' => 'nosniff',
                DocumentController::NOTICE_HEADER => 'addons.payload',
                ReaderGate::DECISION_HEADER => $decisionHeader,
            ],
        );
    }

    /**
     * The document path, canonicalised, or null when it is not one.
     *
     * 🛑 An absent parameter is a **valid** request and means the host root —
     * §8.9.7's empty path. A runtime loaded on a version-root document sends
     * `/`, and an `api_only` consumer asking for nothing in particular gets the
     * same answer.
     */
    private function pathFrom(Request $request): ?string
    {
        $raw = $request->query('path');

        if ($raw === null) {
            return '/';
        }

        if (! is_string($raw) || $raw === '') {
            return '/';
        }

        if (strlen($raw) > self::MAX_PATH_BYTES) {
            return null;
        }

        /*
         * Only the path component. A runtime that sent the whole URL — because
         * `location.pathname` became `location.href` in somebody's edit — must
         * not have its query string read as path segments.
         */
        $path = parse_url($raw, PHP_URL_PATH);

        if (! is_string($path) || $path === '' || ! str_starts_with($path, '/')) {
            return null;
        }

        /*
         * 🛑 §8.9.6's canonical form, applied to reader input rather than
         * assumed. {@see \App\Http\Middleware\RejectNonCanonicalPath} ran
         * against `/_/addons` and not against this parameter, so the check
         * happens here or the parameter is a hole beside a locked door.
         */
        return CanonicalPath::isCanonical($path) ? $path : null;
    }

    /**
     * Every listed version this reader may be told about, keyed by hex id.
     *
     * 🛑 §8.12.9's "flyout … filtered", one gate call per version. The cheap
     * alternative — filtering on the `visibility` column — is wrong for the
     * reason {@see GeneratedArtifacts} records: §8.2.10 makes the
     * project's visibility dominate the version's, and a `mount_exposure`
     * override narrows per domain, so a column check would advertise a public
     * version of a `members` project.
     *
     * @return array<string, ProjectVersion>
     */
    private function authorisedVersions(SnapshotMount $mount, ReaderContext $reader): array
    {
        /** @var list<ProjectVersion> $candidates */
        $candidates = ProjectVersion::withoutGlobalScopes()
            ->where('project_id', $mount->project->id)
            ->where('active', true)
            ->where('listed', true)
            ->where('published', true)
            ->whereNotNull('published_manifest_id')
            ->get()
            ->all();

        $rows = [];

        foreach ($candidates as $row) {
            $version = $this->snapshotVersionFor($mount, $row);

            if (! $version instanceof SnapshotVersion) {
                continue;
            }

            $decision = $this->gate->authorise(
                mount: $mount,
                version: $version,
                language: $version->language,
                /*
                 * The version root rather than the page being read. The question
                 * is "may this reader be told this version exists", and §8.12.9
                 * already states that path-scoped rules are best-effort for
                 * derived surfaces — asking about a path that may not exist in
                 * that version would be answering a different question.
                 */
                path: '',
                surface: AccessSurface::Addons,
                reader: $reader,
            );

            if ($decision->allowed) {
                $rows[bin2hex($row->id)] = $row;
            }
        }

        return $rows;
    }

    /**
     * §8.6.11's answer for every version in the list.
     *
     * @param  array<string, ProjectVersion>  $rows
     * @return array<string, bool>
     */
    private function pageExistence(array $rows, string $remainder): array
    {
        if ($remainder === '') {
            /*
             * The version root, which every published version has by definition
             * — that is what a non-null `published_manifest_id` means. So no
             * manifest is read at all. §9.2's budget is the reason: a reader
             * landing on a version root is the common case, and the common case
             * must not cost one manifest read per version in the flyout.
             */
            return array_map(static fn (ProjectVersion $row): bool => true, $rows);
        }

        /*
         * 🛑 §8.9.7's mapping, not the raw remainder. Asking the manifest for
         * `html/guide/` finds nothing in a tree that holds
         * `html/guide/index.html` — see PageExistence::manifestPathFor().
         */
        return $this->pages->across(array_values($rows), PageExistence::manifestPathFor($remainder));
    }

    /**
     * §8.6.13's notice, built from the same collaborators the document uses.
     *
     * 🛑 **{@see Translations} and {@see CanonicalLocations}, not a second
     * reading of the manifest.** {@see DocumentController} builds this notice
     * for the response header from these two classes; building it here from the
     * same two is what lets `AddonsNoticeAgreementTest` assert that the payload
     * and the header say the same thing about the same path. A banner that
     * disagreed with the header would be two answers to "what happened", and
     * §8.6.13's whole subject is a reader being told the truth about a missing
     * translation.
     *
     * @param  array<string, bool>  $pageExists
     */
    private function noticeFor(
        SnapshotMount $mount,
        RouteOutcome $route,
        ?SnapshotVersion $version,
        string $remainder,
        array $pageExists,
    ): ?TranslationNotice {
        $location = $this->canonical->for($mount->project->id, $mount->project->routingEpoch);

        if (! $location instanceof CanonicalLocation) {
            return null;
        }

        /*
         * The project publishes nothing in the language the URL asked for. The
         * resolver already decided this and carried the language on the
         * rejection for exactly this purpose — see
         * {@see RouteOutcome::rejectedIn()}.
         */
        if ($route->reason === RejectionReason::LanguageNotFound && $route->language !== '') {
            return new TranslationNotice(
                TranslationNotice::LANGUAGE_ABSENT,
                $route->language,
                $this->translations->languageRoots($mount->project, $location),
            );
        }

        /*
         * The language exists, the version resolved, and the page is not in it.
         * `$pageExists` holds the manifest's answer for every version in the
         * flyout including this one, so the miss costs nothing extra.
         */
        if ($version === null || $remainder === '' || ($pageExists[bin2hex($version->id)] ?? true)) {
            return null;
        }

        $elsewhere = [];

        foreach ($this->translations->pagesFor($mount->project, $version, $remainder, $location) as $page) {
            if ($page['language'] === $version->language) {
                /*
                 * The page exists in the language being served and the manifest
                 * lookup missed — a disagreement between two readings of one
                 * manifest rather than a translation gap. Reported as nothing,
                 * which is what {@see DocumentController} does with it too:
                 * inventing a translation banner would hide the disagreement.
                 */
                return null;
            }

            $elsewhere[] = ['language' => $page['language'], 'href' => $location->origin.$page['path']];
        }

        return $elsewhere === []
            ? null
            : new TranslationNotice(TranslationNotice::PAGE_UNTRANSLATED, $version->language, $elsewhere);
    }

    /**
     * Whether this reader may be told anything about the project at all.
     *
     * Used only where the path resolved to no version. The project's default
     * version stands in: a reader allowed to read the version the project points
     * new readers at (§8.6.14) is one allowed to know the project exists, and a
     * reader refused there gets §8.12.23's status rather than a payload.
     */
    private function mayDescribeProject(SnapshotMount $mount, ReaderContext $reader): bool
    {
        $default = $mount->project->defaultVersion();

        if (! $default instanceof SnapshotVersion) {
            /*
             * No servable default version. There is nothing to describe and
             * nothing to leak, so the payload is served: it carries the
             * installation theme and an empty flyout, which is exactly what a
             * reader of a branded 404 on a project with nothing published
             * should see.
             */
            return true;
        }

        return $this->gate->authorise(
            mount: $mount,
            version: $default,
            language: $default->language,
            path: '',
            surface: AccessSurface::Addons,
            reader: $reader,
        )->allowed;
    }

    /** The snapshot's view of a row, when the mount exposes it. */
    private function snapshotVersionFor(SnapshotMount $mount, ProjectVersion $row): ?SnapshotVersion
    {
        foreach ($mount->project->versions as $version) {
            if ($version->id === $row->id && $mount->exposes($version->slug)) {
                return $version;
            }
        }

        return null;
    }

    /**
     * A refusal, with no body and no cache entry.
     *
     * 🛑 No body, because there is nothing a refused reader may be told. The
     * status is the project's §8.12.23 preference where one applies and 404
     * otherwise, and {@see DocumentController::NOTICE_HEADER} names the rule
     * that refused — which is what an operator debugging a missing flyout needs
     * and is observable from outside without disclosing anything.
     */
    private function refuse(int $status, string $notice = 'addons.not_found'): Response
    {
        return new Response('', $status, [
            ...CachePolicy::forAddons()->headers(),
            'X-Content-Type-Options' => 'nosniff',
            DocumentController::NOTICE_HEADER => $notice,
        ]);
    }
}
