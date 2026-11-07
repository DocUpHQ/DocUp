<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Readers;

use App\Access\AccessSurface;
use App\Access\ReaderGate;
use App\Http\Controllers\Serving\DocumentController;
use App\Readers\Grants\GrantMinter;
use App\Readers\ReaderResolver;
use App\Readers\ReaderSessions;
use App\Serving\Resolver;
use App\Serving\RouteKind;
use App\Serving\RoutingSnapshotLoader;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * §20.2's `/_/authz`: §8.12.13's **Tier B** subrequest endpoint.
 *
 * > "**Tier B (scale, no edge scripting):** plain nginx `auth_request` with a
 * > cached subrequest keyed on an **opaque** cache-key cookie carrying no
 * > session material, so one PHP call authorises a 60-asset page. The authz
 * > endpoint emits only 2xx/401. 🛑 With a php-fpm upstream the directive family
 * > is **`fastcgi_cache`**, not `proxy_cache`; the cache key MUST combine host,
 * > opaque cookie and directory, and the **401 MUST be cached too** or an
 * > unauthenticated crawler costs one PHP call per asset."
 *
 * ## 🛑 Two vocabularies, and the endpoint must not confuse them
 *
 * §8.12.24 is explicit: "The Tier B subrequest endpoint's 2xx/401 vocabulary is
 * an internal protocol between the application and the proxy and MUST NOT leak
 * a 401 to a client that §8.12.23 says gets a 404."
 *
 * So this endpoint speaks **204 or 401 and nothing else**, and that 401 means
 * "refuse this subrequest" rather than "challenge this reader". nginx turns it
 * into whatever `error_page` says — which in the shipped configuration is the
 * application's own 404 handler, so the reader's response comes from §8.12.23's
 * rules and not from this status code. An operator who wired the 401 straight
 * through would publish the existence of every private project, which is why
 * the compose configuration ships the `error_page` and the comment that says so.
 *
 * 🛑 **`OnlyFromLoopback` is deliberately NOT applied.** §8.12.13's Tier B has
 * nginx issue the subrequest, and nginx reaches php-fpm over the app network
 * rather than from loopback. What makes the endpoint safe to expose is that it
 * grants nothing: it reads the same cookies the request already carried, makes
 * the same decision §12.3 would make for the document, and returns a status.
 * Calling it directly is indistinguishable from fetching the document.
 */
final readonly class AuthzController
{
    /**
     * 🛑 The cache lifetime nginx is told to honour for a **2xx**.
     *
     * Capped at the grant TTL ceiling, because that is the longest a decision
     * may outlive the epoch it was made under. §8.12.15's one-request bound for
     * Tier B is preserved by the cache key rotating with the grant — see
     * {@see ReaderSessions::rotateCacheKey()} — so an epoch bump
     * does not have to purge anything: the next request presents a key the
     * cache has never seen.
     */
    private const int ALLOW_CACHE_SECONDS = GrantMinter::MAX_TTL_SECONDS;

    /**
     * 🛑 And for a **401**, which §8.12.13 requires to be cached too.
     *
     * "or an unauthenticated crawler costs one PHP call per asset" — the
     * measurement in ADR 0005 is that one page is sixty assets, so an
     * uncached denial turns one crawl of a private project into sixty PHP
     * invocations. Shorter than the allow, because a denial that becomes an
     * allow is somebody signing in and waiting is worse than a wasted call.
     */
    private const int DENY_CACHE_SECONDS = 30;

    public function __construct(
        private RoutingSnapshotLoader $snapshots,
        private Resolver $resolver,
        private ReaderGate $gate,
        private ReaderResolver $readers,
    ) {}

    public function __invoke(Request $request): Response
    {
        /*
         * 🛑 The path comes from nginx's `X-Original-URI`-equivalent — the
         * `uri` query parameter in the shipped configuration — because an
         * `auth_request` subrequest's own URI is `/_/authz`, not the document's.
         *
         * 🛑 And it is a **path**, re-normalised through the same resolver the
         * document controller uses. §8.9.4 forbids resolving a project from
         * anything but the host and path, and the host here is the real one:
         * nginx passes the client's `Host` through to the subrequest, which is
         * what makes this endpoint answer for the right domain at all.
         */
        $uri = (string) $request->query('uri', '/');
        $path = (string) (parse_url($uri, PHP_URL_PATH) ?: '/');

        $snapshot = $this->snapshots->load((string) $request->getHost());

        if (! $snapshot->servable || $snapshot->domainId === null) {
            return self::deny();
        }

        $route = $this->resolver->resolveRoute($snapshot, $path);

        if ($route->kind !== RouteKind::Resolved || $route->mount === null || $route->version === null) {
            /*
             * 🛑 A path that does not resolve is denied, not allowed. The
             * subrequest's job is to gate the file server, and a file the
             * resolver cannot account for must not be served because the
             * authorisation layer had no opinion about it.
             */
            return self::deny();
        }

        $reader = $this->readers->establish(
            $request,
            $snapshot->domainId,
            $route->mount->project,
            AccessSurface::Proxy,
        );

        $decision = $this->gate->authorise(
            mount: $route->mount,
            version: $route->version,
            language: $route->language,
            path: $route->remainder,
            surface: AccessSurface::Proxy,
            reader: $reader->context,
        );

        if (! $decision->allowed) {
            return self::deny($decision->header());
        }

        return self::allow($decision->header());
    }

    /**
     * 🛑 204, with no body and no content type.
     *
     * nginx discards an `auth_request` response body, so sending one would be
     * bytes generated for nobody — and a 200 with a body is the shape that
     * tempts an operator to proxy this endpoint to a client.
     */
    private static function allow(string $decision): Response
    {
        return new Response('', 204, [
            'Cache-Control' => 'private, max-age='.self::ALLOW_CACHE_SECONDS,
            /*
             * 🛑 `Vary: Cookie` even though nginx's cache key already includes
             * the cookie. The directive is what any *other* cache in the path
             * reads, and §9.3.2's rule — private content never carries a public
             * cache directive — has to hold for this endpoint as well as for a
             * document.
             */
            'Vary' => 'Cookie',
            DocumentController::NOTICE_HEADER => 'authz.tier_b',
            ReaderGate::DECISION_HEADER => $decision,
        ]);
    }

    /** 🛑 401, cached, and meaning "refuse the subrequest" (§8.12.24). */
    private static function deny(string $decision = 'deny'): Response
    {
        return new Response('', 401, [
            'Cache-Control' => 'private, max-age='.self::DENY_CACHE_SECONDS,
            'Vary' => 'Cookie',
            DocumentController::NOTICE_HEADER => 'authz.tier_b',
            ReaderGate::DECISION_HEADER => $decision,
        ]);
    }
}
