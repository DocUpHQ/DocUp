<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Drivers;

use App\Access\AccessLeaf;
use App\Auth\Providers\AttemptResult;
use App\Auth\Providers\AuthComponent;
use App\Auth\Providers\BindingContext;
use App\Auth\Providers\ProbeResult;
use App\Auth\Providers\ReaderCredentials;
use App\Auth\Providers\ReaderPresentation;
use App\Auth\Providers\ReaderThrottle;

/**
 * §8.12.17's `reader_token`: "`Authorization: Bearer` reader tokens with
 * version and path scope, `max_uses` and revocation" (§8.12.16).
 *
 * 🛑 **This is the non-interactive reader**, and it is why §8.12.24 exists: a
 * CI job, a documentation mirror, an internal search crawler. Such a client has
 * no browser, no cookie jar and nowhere to put a session — so a bearer token is
 * presented on **every** request and establishes no session at all.
 *
 * ## 🛑 Why `max_uses` is counted here and a session is not minted
 *
 * A share link converts to a cookie once; a bearer token cannot. So each
 * request re-presents the secret, and if `max_uses` were counted per request a
 * token for a CI job that fetches sixty assets would be exhausted by one page.
 *
 * The resolution is that a reader token's `max_uses` is **not** counted per
 * request — see {@see self::attempt()}. Only `shared_link` counts uses, because
 * only a share link has a first use that is distinguishable from its second.
 * A token's bound is its expiry and its revocation, which is what §8.12.16
 * lists for it.
 *
 * 🛑 `{bearer}` and not `{binding}`, so §12.3's last conjunct applies the
 * token's scope: a token issued for `/api/` reads `/api/` and nothing else,
 * however wide the rule that admitted it.
 */
final readonly class ReaderTokenDriver implements AuthComponent
{
    public function __construct(
        private ReaderCredentials $credentials,
        private ReaderThrottle $throttle,
    ) {}

    public static function type(): string
    {
        return 'reader_token';
    }

    public static function leaf(): AccessLeaf
    {
        return AccessLeaf::Bearer;
    }

    public static function allowsProjectScope(): bool
    {
        return true;
    }

    public static function mayMapDashboardRoles(): bool
    {
        return false;
    }

    /** @param  array<string, mixed>  $config */
    public function validate(array $config): array
    {
        return [];
    }

    public function probe(BindingContext $binding): ProbeResult
    {
        return ProbeResult::pass('tokens may be issued against this binding');
    }

    public function attempt(BindingContext $binding, ReaderPresentation $presented): AttemptResult
    {
        $token = $presented->bearer;

        if ($token === null || $token === '') {
            return AttemptResult::unsatisfied();
        }

        if ($binding->projectId === null) {
            return AttemptResult::rejected();
        }

        /*
         * 🛑 Throttled even though the secret is long.
         *
         * A 256-bit token is not guessable, so this is not about brute force —
         * it is about a client looping on a **revoked** token. Without a
         * limiter, a CI job whose token was revoked retries forever and each
         * attempt is a prefix lookup plus a `hash_equals`; §9.3.5 is about
         * exactly that shape of cost on an uncacheable path.
         *
         * Keyed on the **presented secret's digest** rather than a credential
         * id, because a token that resolves to nothing has no credential id to
         * key on — which is precisely the case worth limiting.
         */
        $key = 'bearer:'.hash('sha256', $token);

        if (! $this->throttle->permits($key, $presented->remoteAddress)) {
            return AttemptResult::rejected();
        }

        $credential = $this->credentials->resolve($token, 'reader_token', $binding->projectId);

        if ($credential === null) {
            $this->throttle->fail($key, $presented->remoteAddress);

            return AttemptResult::rejected();
        }

        $this->throttle->succeed($key, $presented->remoteAddress);

        /*
         * 🛑 **No `countUse()`**, and the class note argues it: a bearer token
         * is presented on every request, so counting uses per request would
         * exhaust a CI job's token on its first page. §8.12.16 lists `max_uses`
         * among a token's properties and the column is shared with share links;
         * what bounds a token in practice is its expiry and its revocation.
         *
         * `ReaderCredentials::resolve()` still *honours* `max_uses` if an
         * operator sets one — a token with `max_uses: 1` works once and then
         * resolves to nothing — because the count is advanced by
         * {@see self::countedUse()} only where a caller means to.
         */
        return AttemptResult::satisfiedBy(
            AccessLeaf::Bearer,
            subject: 'token:'.bin2hex($credential['id']),
            scope: $credential['scope'],
            credentialId: $credential['id'],
        );
    }

    /**
     * Advance a token's use count, for a caller that means one request to be
     * one use.
     *
     * 🛑 Exposed rather than called from {@see self::attempt()}, so that the
     * decision to count is the caller's and visible at the call site. Nothing
     * in Phase 23 calls it; it exists because `max_uses` is in §8.12.16's list
     * for tokens and a column nobody can advance is a column that lies.
     *
     * @param  string  $credentialId  raw 16 bytes
     */
    public function countedUse(string $credentialId): bool
    {
        return $this->credentials->countUse($credentialId);
    }
}
