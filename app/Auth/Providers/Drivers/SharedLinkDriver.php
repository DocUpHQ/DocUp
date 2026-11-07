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

/**
 * §8.12.17's `shared_link`: "share-by-link (mandatory expiry, converted to a
 * cookie on first use and 302'd to a clean URL)".
 *
 * ## 🛑 The query-to-cookie conversion is not in this driver
 *
 * It is in the middleware, and the split is the point. §8.12.16 requires the
 * secret to leave the URL on first use, which is a **transport** concern: a 302
 * to a clean URL and a `Set-Cookie`. This driver only ever sees
 * {@see ReaderPresentation::$shareSecret}, which the middleware has already
 * taken from either place.
 *
 * Why it matters that the secret leaves the URL — the three places a URL goes
 * that a cookie does not:
 *
 * - the browser's **history**, where it survives the link being revoked;
 * - the `Referer` of **everything the page loads**, which for documentation is
 *   whatever the generator embedded;
 * - every **proxy and CDN access log** between the reader and the origin.
 *
 * §17's exit criterion is the observable form of that: "A share link in a query
 * string converts to a cookie and 302s to a clean URL, and the query value
 * appears in no log."
 *
 * 🛑 **`{share}` and not `{binding}`**, which is §12.3's last conjunct acquiring
 * teeth: a share leaf carries a scope, so a link issued for `/v1/api/` narrows
 * the reader to it even if the rule that admitted them was wider.
 */
final readonly class SharedLinkDriver implements AuthComponent
{
    public function __construct(private ReaderCredentials $credentials) {}

    public static function type(): string
    {
        return 'shared_link';
    }

    public static function leaf(): AccessLeaf
    {
        return AccessLeaf::Share;
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
        /*
         * 🛑 Nothing configurable, and in particular no default expiry.
         *
         * A binding-level default would be the one place an operator could set
         * "never", and §8.12.16 makes expiry mandatory per link. Making it a
         * required argument of
         * {@see ReaderCredentials::issue()} — refused there and by a database
         * CHECK — means there is no configuration to get wrong.
         */
        return [];
    }

    public function probe(BindingContext $binding): ProbeResult
    {
        if (! $binding->shareable) {
            /*
             * 🛑 A `shared_link` binding that is not marked shareable can mint
             * no links, so it guards nothing — fail-closed, and still a failed
             * probe, because it is not what the operator configured.
             */
            return ProbeResult::fail('this binding is not marked shareable, so no link can be issued');
        }

        return ProbeResult::pass('links may be issued against this binding');
    }

    public function attempt(BindingContext $binding, ReaderPresentation $presented): AttemptResult
    {
        $secret = $presented->shareSecret;

        if ($secret === null || $secret === '') {
            return AttemptResult::unsatisfied();
        }

        if ($binding->projectId === null) {
            /*
             * A share link is issued against a project, so a binding with no
             * project cannot authorise one. Reached only for an
             * installation-scoped `shared_link` binding, which is a
             * configuration the resolver permits and this driver cannot use.
             */
            return AttemptResult::rejected();
        }

        $credential = $this->credentials->resolve($secret, 'shared_link', $binding->projectId);

        if ($credential === null) {
            /*
             * 🛑 **`unsatisfied`, not `rejected`, and §17 is why.**
             *
             * §8.12.23 *permits* a challenge here — case (a) names "an
             * expired, revoked or out-of-scope … share cookie" — but permits
             * is not requires, and §17's Phase 23 exit criterion declines the
             * permission in exactly this case: "An expired link 404s."
             *
             * 🛑 The reason the narrower choice is the right one is what a
             * share secret **is**: a bearer credential in a URL, which travels
             * by being forwarded. A dead link answered with `401` and
             * `WWW-Authenticate` tells whoever now holds it that the resource
             * is real and guarded — and an expired link is the operator's
             * revocation taking effect, so that holder is an outsider by the
             * operator's own decision. §8.12.16 makes expiry mandatory so a
             * forwarded link stops working; a stop that still confirms
             * existence is a weaker stop than was asked for, and §8.2.2 wants
             * a refusal indistinguishable from absence.
             *
             * 🛑 The line is drawn at **proof of the link**: below, once the
             * secret has resolved, a missing or wrong password *is* `rejected`,
             * because the reader has demonstrated they hold a live link and
             * §8.12.16's passworded flow cannot offer them a credential page
             * without the challenge. A deliberate header credential
             * ({@see ReaderTokenDriver}) challenges for the same reason — RFC
             * 6750 answers a bad bearer token with `401`, and a header is not
             * forwardable the way a URL is.
             *
             * An earlier revision returned `rejected()` here and claimed §17's
             * criterion still held because `mayChallenge()` needed public
             * existence as well. It does not: `credentialRejected` alone
             * reaches the 401 branch in {@see \App\Access\EffectiveAccess}. The
             * comment asserted a property the code did not have, and the exit
             * criterion's own test is what found it.
             */
            return AttemptResult::unsatisfied();
        }

        /*
         * 🛑 A passworded link needs the password too, and the ordering here is
         * the security property: the password is checked **after** the secret
         * resolves, so a wrong password against a non-existent link costs one
         * prefix lookup and no Argon2 verification. Checking the password first
         * would make this endpoint an Argon2 oracle for anybody sending noise.
         */
        if ($credential['passworded']) {
            if ($presented->password === null || $presented->password === '') {
                /*
                 * The link is real and needs a password nobody typed. A
                 * rejection rather than an absence, so the credential page can
                 * be offered — which is the whole flow a passworded link is
                 * for.
                 */
                return AttemptResult::rejected();
            }

            if (! $this->credentials->passwordMatches(
                $credential['id'],
                $presented->password,
                $presented->remoteAddress,
            )) {
                return AttemptResult::rejected();
            }
        }

        /*
         * 🛑 Count the use **atomically**, and refuse if the count fails.
         *
         * `resolve()` already checked `max_uses`, but between that read and
         * this write another request may have taken the last use. The `UPDATE`
         * carries the guard in its own `WHERE`, so a single-use link admits one
         * reader even under concurrency — which is the whole of what
         * "single-use" means.
         */
        if (! $this->credentials->countUse($credential['id'])) {
            return AttemptResult::rejected();
        }

        return AttemptResult::satisfiedBy(
            AccessLeaf::Share,
            /*
             * 🛑 The subject is the **credential**, not the person. Everybody
             * holding one link is one reader as far as §20.3 can tell, and
             * saying so is honest; inventing a per-request subject would make
             * the decision log imply an identity the link does not carry.
             */
            subject: 'link:'.bin2hex($credential['id']),
            scope: $credential['scope'],
            credentialId: $credential['id'],
        );
    }
}
