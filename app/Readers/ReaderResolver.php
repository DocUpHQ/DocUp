<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers;

use App\Access\AccessDecision;
use App\Access\AccessSurface;
use App\Access\EffectiveAccess;
use App\Access\PolicySimulator;
use App\Access\ReaderContext;
use App\Auth\Providers\ProviderResolver;
use App\Auth\Providers\ReaderPresentation;
use App\Http\Controllers\Readers;
use App\Readers\Grants\GrantMinter;
use App\Readers\Grants\GrantVerifier;
use App\Serving\SnapshotProject;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Cookie;

/**
 * 🛑 The seam between a request's cookies and §12.3's one decision.
 *
 * {@see ReaderContext}'s own comment, written in Phase 21, says what this class
 * is for: "Phase 22 fills it from `docs_sessions` and a verified grant; Phase 21
 * constructs it directly". That is the whole of this class's job, and the reason
 * it is a class rather than a few lines in a controller is that **four surfaces
 * need it** (§8.12.21's proxy, download, search and addons) and a reader
 * established differently on any one of them would be a disclosure on that one.
 *
 * ## 🛑 §8.12.13's two tiers, from one code path
 *
 * > "**Tier A (default):** every documentation request authorised in PHP, bytes
 * > handed off by internal redirect, one signature verification, zero database
 * > round-trips."
 *
 * The ladder is implemented as a preference order over what the request carried,
 * not as two implementations:
 *
 * 1. A **grant** cookie that verifies: one signature, no database. The grant
 *    carries the reader's established level, so a context is reconstructed from
 *    claims this installation signed less than ten minutes ago.
 * 2. Otherwise a **session** cookie: one indexed read, roles re-derived, and a
 *    fresh grant minted if the request is then allowed.
 * 3. Otherwise anonymous.
 *
 * 🛑 And in every one of the three, {@see EffectiveAccess} still
 * decides. §8.12.14 forbids "a public fast path that bypasses an authorisation
 * decision"; a grant shortens the path to the decision's *inputs* and never
 * replaces the decision. The difference is observable: flip a project to private
 * and the next request's grant still verifies, and is still refused, because the
 * epoch moved.
 */
final readonly class ReaderResolver
{
    public function __construct(
        private GrantVerifier $verifier,
        private GrantMinter $minter,
        private ReaderSessions $sessions,
        private ProviderResolver $providers,
    ) {}

    /**
     * Establish the reader from this request's cookies.
     *
     * @param  string|null  $domainId  raw 16 bytes from the resolved snapshot;
     *                                 🛑 null means the host answered nothing,
     *                                 in which case no cookie can establish
     *                                 anything — there is no origin to have
     *                                 been established against
     * @param  int|null  $now  unix seconds; null reads the clock
     */
    public function establish(
        Request $request,
        ?string $domainId,
        SnapshotProject $project,
        AccessSurface $surface = AccessSurface::Proxy,
        ?int $now = null,
    ): EstablishedReader {
        if ($domainId === null) {
            return EstablishedReader::anonymous();
        }

        $now ??= time();
        $epoch = $project->combinedEpoch();

        $presented = self::cookie($request, ReaderCookies::GRANT);

        if ($presented !== null) {
            $grant = $this->verifier->grantFor($presented, $domainId, $epoch, $surface, $now);

            if ($grant !== null) {
                /*
                 * 🛑 The project is checked here and not inside the verifier,
                 * because the verifier does not know what a mount is. One
                 * documentation host may carry mounts from several projects
                 * (§8.7), so a grant minted for project A on this domain must
                 * not establish a reader on project B's mount of the same
                 * domain.
                 */
                if (hash_equals($grant->projectId, $project->id)) {
                    return new EstablishedReader(
                        context: $grant->readerContext(),
                        grant: $grant,
                    );
                }
            }

            /*
             * Something was presented and is not usable. Fall through to the
             * session — a stale grant beside a live session is the ordinary
             * case, once every grant TTL — but remember that a credential was
             * refused, because §8.12.23's case (a) turns on it.
             */
            return $this->fromSession(
                $request,
                $domainId,
                $project,
                $now,
                credentialRejected: $this->verifier->looksLikeGrant($presented),
            );
        }

        return $this->fromSession($request, $domainId, $project, $now, credentialRejected: false);
    }

    /**
     * Mint a grant and the Tier B cache key for an allowed request.
     *
     * 🛑 Called **only** after an allow, and the signature enforces it: the
     * minter refuses a denial outright. Returning cookies rather than setting
     * them keeps this class out of the response, which is what lets the four
     * surfaces attach them in whatever way each one's response is built.
     *
     * @param  string  $domainId  raw 16 bytes
     * @return list<Cookie> the grant and the cache key, or empty when the
     *                      request established no session to mint against
     */
    public function issue(
        AccessDecision $decision,
        EstablishedReader $reader,
        SnapshotProject $project,
        string $domainId,
        string $versionId,
        string $versionSlug,
        AccessSurface $surface = AccessSurface::Proxy,
        ?int $now = null,
    ): array {
        if (! $reader->needsGrant() || $reader->session === null || ! $decision->allowed) {
            return [];
        }

        $token = $this->minter->mint(
            decision: $decision,
            reader: $reader->context,
            session: $reader->session,
            domainId: $domainId,
            versionId: $versionId,
            versionSlug: $versionSlug,
            authzEpoch: $project->authzEpoch,
            identityEpoch: $project->identityEpoch,
            surface: $surface,
            now: $now,
        );

        $cookies = [ReaderCookies::grant($token)];

        /*
         * §8.12.13's Tier B key, re-issued beside the grant so the two always
         * expire together. "carries no session material": the value is the
         * session's own second secret, which the application can look up and
         * which tells nginx nothing.
         */
        $cacheKey = $this->sessions->rotateCacheKey($reader->session);

        if ($cacheKey !== null) {
            $cookies[] = ReaderCookies::cacheKey($cacheKey);
        }

        return $cookies;
    }

    /**
     * Step 2 of the ladder: a session cookie, read once.
     */
    private function fromSession(
        Request $request,
        string $domainId,
        SnapshotProject $project,
        int $now,
        bool $credentialRejected,
    ): EstablishedReader {
        $handle = self::cookie($request, ReaderCookies::SESSION);
        $session = null;
        $sessionRejected = false;

        if ($handle !== null) {
            $session = $this->sessions->resolve($handle, $project->id, $domainId, $now);

            /*
             * 🛑 A session handle that resolves to nothing **is** a rejected
             * credential, even though nothing cryptographic failed. §8.12.23's
             * case (a) names "an expired, revoked or out-of-scope grant, bearer
             * token or share cookie"; a revoked session handle is the same
             * fact, and a reader whose session an administrator ended should be
             * asked to sign in again rather than told the project vanished.
             */
            $sessionRejected = $session === null;
        }

        return $this->establishAs(
            $session,
            $project,
            new ReaderPresentation(
                bearer: self::bearer($request),
                shareSecret: self::cookie($request, ReaderCookies::SHARE),
                /*
                 * 🛑 §8.12.16's password, from the request rather than a
                 * session.
                 *
                 * It is read on **every** request rather than exchanged once
                 * for a cookie, which is a deliberate difference from the share
                 * link. A share link's secret is in a URL and has to leave it;
                 * a password is typed, and converting it to a long-lived cookie
                 * would mean storing a reusable credential in the browser for a
                 * secret the operator can only rotate by telling everybody.
                 *
                 * 🛑 The parameter is namespaced for the reason
                 * {@see \App\Http\Middleware\ConvertShareLink::PARAMETER} is: a
                 * bare `password` would collide with a generator's own form
                 * handling, and a collision here means somebody's search box
                 * being treated as a credential.
                 */
                password: self::password($request),
                /*
                 * 🛑 `$request->ip()`, never a header. §8.9.4 forbids a trusted
                 * request header anywhere in the request path, so this is the
                 * `TrustProxies`-resolved address and not `X-Forwarded-For` as
                 * sent — the same source
                 * {@see \App\Http\Middleware\OnlyFromLoopback} reads, and for
                 * the same reason.
                 */
                remoteAddress: $request->ip(),
            ),
            credentialRejected: $credentialRejected || $sessionRejected,
        );
    }

    /**
     * 🛑 The merge of a session and every binding in scope, with **no request
     * in sight**.
     *
     * Everything above this line is about what a request carried; everything
     * below is about what those credentials mean. The split is here rather than
     * nowhere because §8.12.25's policy simulator needs the second half and
     * must not have the first: an operator asking "as this identity, on this
     * URL" has no cookies to read, and a simulator that built its own
     * {@see ReaderContext} would be a second answer to the question §17 insists
     * has one.
     *
     * So {@see PolicySimulator} calls this with a
     * {@see SessionRecord} it assembled from stored facts and a presentation of
     * the credentials the operator chose to hypothesise. Every merge rule —
     * §8.12.19's degraded short-circuit, the session floor, the leaf union,
     * §12.3's per-leaf scopes — runs here and nowhere else, so the simulator
     * cannot drift from the serving path by construction rather than by
     * discipline.
     *
     * 🛑 **This method performs no writes and must not acquire any.** The
     * drivers it drives are read-only today (no rate-limit slot, no use count,
     * no audit row), which is what makes it safe for a simulation to run the
     * real thing. A driver that later wants to record something must record it
     * at its own call site in {@see Readers} and not
     * here, or every simulation becomes a write.
     *
     * @param  SessionRecord|null  $session  null for a reader with no session,
     *                                       which is the anonymous and
     *                                       credential-only cases both
     */
    public function establishAs(
        ?SessionRecord $session,
        SnapshotProject $project,
        ReaderPresentation $presented,
        bool $credentialRejected,
    ): EstablishedReader {
        /*
         * 🛑 **Phase 23: the bindings run even when a session resolved.**
         *
         * The obvious shape is "session, or else providers", and it is wrong:
         * §12.3 lets a rule name a specific binding, so a dashboard member who
         * also holds a share link for `/internal/` must satisfy *both* leaves
         * or a rule naming `{share}` would refuse them. And §8.12.19's degraded
         * check has to run whatever else succeeded, or a project with a healthy
         * portal and a broken IdP would serve from the portal and never report
         * the IdP.
         *
         * So the session supplies the **floor** — `members`, which no driver
         * can reach on its own — and the providers add leaves on top.
         */
        $sessionContext = $session === null ? null : $this->sessions->contextFor($session);

        $outcome = $this->providers->resolve($project, $presented->withSession(
            $sessionContext?->subject,
            /*
             * 🛑 §12.3 lets a rule name a specific binding, so a
             * session-backed leaf has to say *which* one vouched for it —
             * otherwise `{"driver": "portal_session"}` and
             * `{"driver": "oidc"}` would both be satisfied by any session, and
             * a project could not write one rule per audience.
             *
             * Null for a member, which is what makes `oidc` refuse them.
             */
            $session === null ? null : $this->sessions->bindingFor($session),
        ));

        /*
         * 🛑 §8.12.19's branded 503, carried on the established reader rather
         * than thrown. The decision function must still run — §8.12.14 forbids
         * a path that bypasses it — and the controller is what turns this into
         * a response, because only the controller knows how to render one.
         */
        if ($outcome->degraded) {
            return new EstablishedReader(
                context: ReaderContext::anonymous(),
                session: $session,
                credentialRejected: $credentialRejected,
                degradedBinding: $outcome->degradedBinding,
            );
        }

        return new EstablishedReader(
            /*
             * 🛑 The session is passed **whole**, not just its level. See
             * {@see ProviderOutcome::toReaderContext()}: taking only the level
             * lost the `{binding}` leaf a Phase 22 member holds on a project
             * with no bindings configured, which is the case §17 requires to
             * keep working.
             */
            context: $outcome->toReaderContext($sessionContext),
            session: $session,
            credentialRejected: $credentialRejected,
        );
    }

    /**
     * §8.12.16's `Authorization: Bearer` reader token.
     *
     * 🛑 Parsed strictly: the scheme is compared case-insensitively because RFC
     * 9110 makes it so, and anything other than exactly one `Bearer` token is
     * nothing. A lenient parse here would be a parse an attacker chooses the
     * shape of.
     */
    /**
     * §8.12.16's submitted password.
     *
     * 🛑 Taken from `input()`, so a POST body and a query string both work —
     * and the credential page P23 does not build will POST it. Read as a
     * string or not at all: an array submitted under this name would otherwise
     * reach `Hash::check()` as `"Array"` and be compared against a real hash.
     */
    public const string PASSWORD_PARAMETER = 'docup_password';

    private static function password(Request $request): ?string
    {
        $value = $request->input(self::PASSWORD_PARAMETER);

        return is_string($value) && $value !== '' ? $value : null;
    }

    private static function bearer(Request $request): ?string
    {
        $header = $request->headers->get('Authorization');

        if (! is_string($header) || $header === '') {
            return null;
        }

        if (preg_match('/^Bearer ([A-Za-z0-9._~+\/-]+=*)$/i', trim($header), $matches) !== 1) {
            return null;
        }

        return $matches[1];
    }

    /**
     * One cookie's value, or null.
     *
     * 🛑 Read through `$request->cookies` (Symfony's bag) rather than Laravel's
     * `Cookie` facade, because the documentation origin has no
     * `EncryptCookies` middleware and must not: §8.12.11 refuses a
     * framework-encrypted grant outright, since "a Laravel-encrypted cookie can
     * only be verified by PHP, foreclosing edge authorisation". Reading the raw
     * bag is what makes this code honest about that — it is the same value the
     * edge sees.
     */
    private static function cookie(Request $request, string $name): ?string
    {
        $value = $request->cookies->get($name);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
