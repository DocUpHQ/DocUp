<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers;

use App\Access\AccessDecision;
use App\Access\AccessSurface;
use App\Access\EffectiveAccess;
use App\Access\ReaderContext;
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

        if ($handle === null) {
            return new EstablishedReader(
                context: ReaderContext::anonymous(),
                credentialRejected: $credentialRejected,
            );
        }

        $session = $this->sessions->resolve($handle, $project->id, $domainId, $now);

        if ($session === null) {
            /*
             * 🛑 A session handle that resolves to nothing **is** a rejected
             * credential, even though nothing cryptographic failed. §8.12.23's
             * case (a) names "an expired, revoked or out-of-scope grant, bearer
             * token or share cookie"; a revoked session handle is the same
             * fact, and a reader whose session an administrator ended should be
             * asked to sign in again rather than told the project vanished.
             */
            return new EstablishedReader(
                context: ReaderContext::anonymous(),
                credentialRejected: true,
            );
        }

        return new EstablishedReader(
            context: $this->sessions->contextFor($session),
            session: $session,
            credentialRejected: $credentialRejected,
        );
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
