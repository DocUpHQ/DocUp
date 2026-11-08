<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Readers;

use App\Auth\Providers\Bindings;
use App\Readers\PkceChallenge;
use App\Readers\ReaderCookies;
use App\Readers\ReaderHandoff;
use App\Readers\ReaderHandoffState;
use App\Readers\ReaderRejection;
use App\Serving\RoutingSnapshotLoader;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * §20.2's `/_/auth/start`: the documentation origin's half of §8.12.10, step 1.
 *
 * 🛑 **On the documentation origin, and the PKCE verifier never leaves it.**
 * That is the whole shape of the handoff: the secret that redeems the code lives
 * in a `__Host-` cookie on the origin that will use it, so the code travelling
 * through the dashboard and back through a URL is worthless to anybody who
 * intercepts it.
 *
 * 🛑 **No session, no CSRF token, no `web` group** — `routes/docs.php`'s own
 * note says why, and this endpoint is the first thing on that origin that sets
 * a cookie at all. It sets exactly one, `__Host-docup_state`, which carries no
 * authority: a stolen verifier redeems nothing without a code, and a code is
 * minted only for a signed-in dashboard user.
 */
final readonly class AuthStartController
{
    public function __construct(
        private RoutingSnapshotLoader $snapshots,
        private ReaderHandoff $handoff,
        private Bindings $bindings,
    ) {}

    public function __invoke(Request $request): Response
    {
        $snapshot = $this->snapshots->load((string) $request->getHost());

        /*
         * 🛑 §8.9.3's hard 404 applies here too. An unknown or unservable host
         * has no origin to establish a session on, and answering anything else
         * would make this endpoint a probe for which hostnames the installation
         * knows about.
         */
        if (! $snapshot->servable || $snapshot->domainId === null) {
            return ReaderRejection::notFound();
        }

        /*
         * 🛑 Where the reader was going, **from the path they asked for and
         * normalised before it is stored**. A `return` parameter is accepted
         * because the reader's own browser supplies it and it is a path on
         * this origin; {@see ReaderHandoff::safeReturnPath()} is what keeps it
         * from becoming an origin, and §8.12.10's rule about the *return URL*
         * is satisfied by the other half — the origin comes from the domain
         * row at redemption and is never carried here at all.
         */
        $returnPath = ReaderHandoff::safeReturnPath((string) $request->query('return', '/'));

        /*
         * Which project? The one whose mount covers the path the reader was
         * trying to reach. A documentation host may carry mounts from several
         * projects (§8.7), so "this host's project" is not a question with one
         * answer — and establishing a session for the wrong one would send the
         * reader back to a page they still cannot read.
         */
        $match = $snapshot->matchFor($returnPath);

        if ($match === null) {
            return ReaderRejection::notFound();
        }

        /*
         * 🛑 The loop breaker. See {@see \App\Readers\HandoffRejection::LoopDetected}:
         * a browser that follows the redirect and then discards the session
         * cookie produces an infinite bounce with a 302 at each end and nothing
         * that looks like an error. §18.10 is the unverified assumption behind
         * that risk, and this is why Phase 22 does not rest on it.
         */
        $state = ReaderHandoffState::fromCookie($request->cookies->get(ReaderCookies::STATE));

        if ($state !== null && $state->attempt >= ReaderHandoff::MAX_ATTEMPTS) {
            return ReaderRejection::cookiesBlocked();
        }

        $pkce = PkceChallenge::create();

        $next = new ReaderHandoffState(
            verifier: $pkce->verifier,
            returnPath: $returnPath,
            attempt: ($state->attempt ?? 0) + 1,
        );

        /*
         * 🛑 Which leg of the dashboard to send the reader to, decided here
         * because this is where the project is already resolved.
         *
         * An active `oidc` or `saml` binding means the project's readers
         * authenticate at an identity provider, so the member handoff — which
         * is behind `auth` — would bounce them to a dashboard login they have
         * no account for. With no such binding, nothing changes from Phase 22.
         *
         * 🛑 The PKCE verifier cookie is set either way and the final hop is
         * `/_/auth/callback` either way, so §8.12.10's mechanism is untouched:
         * every provider leg ends by minting the same handoff code this origin
         * is already waiting for. That is what kept this a choice of URL rather
         * than a second session mechanism — and it is why adding SAML in Phase
         * 25 was one more entry in the list below rather than a new flow.
         *
         * 🛑 **First match wins, and the order is §8.12.3's.**
         * `contextsFor()` returns bindings most-specific-of-type first, so a
         * project that brings its own provider is served by it rather than by an
         * installation-wide one. Where a project has *both* an `oidc` and a
         * `saml` binding the list's order decides, which is a deterministic
         * answer rather than a good one — §8.12.3 gives no precedence between
         * two different types at the same specificity, and inventing one here
         * would be this file deciding policy. The operator's remedy is to not
         * configure two.
         */
        $project = $match->mount->project;

        $viaProvider = null;

        foreach ($this->bindings->contextsFor($project->id, $project->organisationId, $project->authzEpoch) as $binding) {
            if (($binding->type === 'oidc' || $binding->type === 'saml') && $binding->isUsable()) {
                $viaProvider = $binding->type;
                break;
            }
        }

        $redirect = new RedirectResponse(
            $viaProvider === null
                ? $this->handoff->startUrl($snapshot->domainId, $pkce->challenge, $returnPath)
                : $this->handoff->providerStartUrl(
                    $viaProvider,
                    $snapshot->domainId,
                    $pkce->challenge,
                    $returnPath,
                ),
        );

        return $redirect
            ->withCookie(ReaderCookies::state($next->toCookie()))
            /*
             * 🛑 Never cached, anywhere. This response carries a `Set-Cookie`
             * holding a one-use secret; a shared cache storing it would hand
             * the next reader somebody else's verifier. §9.3.2's rule about
             * private content is the same rule.
             */
            ->withHeaders([
                'Cache-Control' => 'private, no-store',
                'Vary' => 'Cookie',
                'X-Robots-Tag' => 'noindex, nofollow',
            ]);
    }
}
