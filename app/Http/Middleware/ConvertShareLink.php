<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Auth\Providers\ReaderCredentials;
use App\Credentials\SecretRedactor;
use App\Readers\ReaderCookies;
use App\Serving\RoutingSnapshotLoader;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * 🛑 §8.12.16's conversion: a share link "converted to a cookie on first use and
 * 302'd to a clean URL".
 *
 * ## 🛑 Why the secret must leave the URL
 *
 * Three places a URL goes that a cookie does not, and all three outlive the
 * link:
 *
 * - the browser's **history**, where it survives the link being revoked and is
 *   synced to every device the reader is signed into;
 * - the `Referer` of **everything the page loads** — and documentation is
 *   whatever the generator embedded, including third-party fonts and analytics;
 * - every **proxy, CDN and load-balancer access log** between the reader and
 *   the origin, which are retained on schedules DocUp does not set.
 *
 * §17's exit criterion is the observable form: "A share link in a query string
 * converts to a cookie and 302s to a clean URL, and the query value appears in
 * no log."
 *
 * 🛑 **DocUp's own logs were already covered**, by Phase 05's
 * {@see SecretRedactor}: its `docup(?:_[a-z]+)?_…` pattern
 * matches a link secret, because §9.1.4 mints every token with a `docup_`
 * prefix. That is a Phase 05 decision paying off five phases later, and it is
 * asserted by a test rather than assumed.
 *
 * ## 🛑 Position in the pipeline
 *
 * **After** {@see RejectNonCanonicalPath}, which §8.9.6 puts before everything:
 * "the rejection happens before any cache lookup or resolution, and its
 * position in the pipeline is the whole of its value". A traversal carrying a
 * share parameter must be rejected as a traversal, not redirected as a link.
 *
 * **Before** the controller, because the whole point is that the controller —
 * and therefore the decision, the log and the response — never sees the URL
 * with the secret in it.
 */
final readonly class ConvertShareLink
{
    /**
     * The query parameter a share link arrives in.
     *
     * 🛑 Namespaced, like everything else DocUp puts in a reader's URL space.
     * A bare `?token=` would collide with a generator's own parameters — MkDocs
     * and Docusaurus both use query strings for search — and a collision here
     * means somebody's search query being treated as a credential.
     */
    public const string PARAMETER = 'docup_share';

    public function __construct(
        private RoutingSnapshotLoader $snapshots,
        private ReaderCredentials $credentials,
    ) {}

    public function handle(Request $request, \Closure $next): Response
    {
        $secret = $request->query(self::PARAMETER);

        if (! is_string($secret) || $secret === '') {
            return $next($request);
        }

        /*
         * 🛑 The clean URL is built by **removing one parameter**, not by
         * truncating the query string. A reader following a link to
         * `?highlight=foo&docup_share=…` keeps their highlight; dropping the
         * whole query would silently change the page they were sent to.
         */
        $clean = self::withoutShareParameter($request);

        $snapshot = $this->snapshots->load((string) $request->getHost());
        $match = $snapshot->servable ? $snapshot->matchFor($request->getPathInfo()) : null;

        if ($match === null) {
            /*
             * 🛑 **Still redirect**, with no cookie. The host or path does not
             * resolve, so there is no project to check the secret against — and
             * the one thing that must happen regardless is that the secret
             * leaves the URL. Leaving it there because the link was wrong is
             * the worst of both outcomes: no access and a leaked credential.
             */
            return self::redirect($clean);
        }

        $credential = $this->credentials->resolve($secret, 'shared_link', $match->mount->project->id);

        if ($credential === null) {
            /*
             * 🛑 Redirect **without setting a cookie**. A junk or revoked
             * secret becomes a junk cookie that makes every subsequent request
             * a rejected credential — which §8.12.23 then challenges rather
             * than refusing — so a reader who clicked a typo'd link would be
             * asked to authenticate on every page of a public site.
             *
             * The secret still leaves the URL, which is the requirement.
             */
            return self::redirect($clean);
        }

        /*
         * The cookie's lifetime is the credential's own, so a link given for a
         * week lasts a week and one given for an hour does not outlive it. The
         * database remains the authority either way — the driver re-checks
         * expiry, revocation and uses on every request — but a cookie that
         * outlived the link would turn every later request into a rejected
         * credential instead of an absent one.
         */
        return self::redirect($clean)
            ->withCookie(ReaderCookies::share($secret, $credential['expiresIn']));
    }

    /**
     * 🛑 A 302 with `Cache-Control: no-store`, and the header is not optional.
     *
     * The response carries a `Set-Cookie` holding a live credential. A shared
     * cache that stored this redirect would hand the next reader somebody
     * else's share link — §9.3.2's failure, arriving behind a 302 that looks
     * like routing.
     *
     * 🛑 And `Referrer-Policy: no-referrer`, because the document the reader is
     * arriving *from* is the URL that still contains the secret: without this,
     * the clean page's own subresource requests would carry the dirty URL in
     * their `Referer` and undo the whole conversion.
     */
    private static function redirect(string $location): RedirectResponse
    {
        return new RedirectResponse($location, 302, [
            'Cache-Control' => 'private, no-store',
            'Vary' => 'Cookie',
            'Referrer-Policy' => 'no-referrer',
            'X-Robots-Tag' => 'noindex, nofollow',
        ]);
    }

    /**
     * The same URL without the share parameter.
     *
     * 🛑 Returns a **path**, never an absolute URL, so this cannot become an
     * open redirect. The destination is built from `getPathInfo()` and the
     * remaining query — both of which are this request's own — and the scheme
     * and host are the browser's to supply.
     */
    public static function withoutShareParameter(Request $request): string
    {
        $query = $request->query->all();

        unset($query[self::PARAMETER]);

        $path = $request->getPathInfo();

        if ($query === []) {
            return $path;
        }

        return $path.'?'.http_build_query($query);
    }
}
