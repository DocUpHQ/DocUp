<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Readers;

use App\Auth\OrganisationContext;
use App\Auth\Providers\Bindings;
use App\Auth\Providers\Oidc\AuthorisationRequest;
use App\Auth\Providers\Oidc\Discovery;
use App\Auth\Providers\Oidc\OidcAudit;
use App\Auth\Providers\Oidc\OidcExchange;
use App\Auth\Providers\Oidc\OidcRefused;
use App\Models\Domain;
use App\Readers\ReaderHandoff;
use App\Readers\ReaderRejection;
use App\Serving\RoutingSnapshotLoader;
use App\Support\Uuid;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * §8.12.18's authorisation request: the dashboard half of an OIDC login.
 *
 * 🛑 **Unauthenticated, and that is the whole point.** The sibling
 * {@see HandoffController} sits behind `auth` because it mints a code for a
 * reader who is already a dashboard user. An OIDC reader is not one and never
 * will be — §8.12.1 keeps the two populations "physically disjoint" — so this
 * route cannot require a session. What it requires instead is a **verified
 * domain** and an **active binding**, both looked up server-side, and neither
 * taken from anything the reader can choose.
 *
 * 🛑 **On the dashboard origin**, because ADR 0008 measured that one fixed
 * callback serves readers arriving from any number of custom domains: "the
 * identity provider never learns which host began the flow". A per-domain
 * callback would mean every custom domain registered with every provider, and
 * the spike's control confirmed providers enforce the registered list strictly.
 *
 * ## What travels, and what does not
 *
 * The reader brings a `domain`, a `challenge` and a `return`. None of the three
 * is trusted as given:
 *
 * - `domain` is an id looked up in `domains`, and a row that cannot serve is a
 *   404 — so the return address is the verified host, never the parameter;
 * - `challenge` is §8.12.10's S256 value, stored and only ever compared;
 * - `return` is normalised by {@see ReaderHandoff::safeReturnPath()} before it
 *   is written, so a stored path cannot later be replayed as an origin.
 *
 * Everything else — `state`, `nonce`, the PKCE verifier — DocUp generates.
 */
final readonly class OidcStartController
{
    public function __construct(
        private RoutingSnapshotLoader $snapshots,
        private Bindings $bindings,
        private Discovery $discovery,
        private OidcExchange $exchange,
        private OrganisationContext $context,
    ) {}

    public function __invoke(Request $request): Response
    {
        $domainId = Uuid::tryToBytes((string) $request->query('domain', ''));
        $challenge = (string) $request->query('challenge', '');
        $returnPath = ReaderHandoff::safeReturnPath((string) $request->query('return', '/'));

        if ($domainId === null) {
            return ReaderRejection::notFound();
        }

        /*
         * 🛑 The challenge is checked here as well as by `ReaderHandoff::mint()`,
         * because a malformed one would be stored now and refused at the far
         * end of a full round trip through an identity provider — which the
         * reader would experience as "signing in does not work" with nothing
         * to go on.
         */
        if (preg_match('/^[A-Za-z0-9_-]{43}$/', $challenge) !== 1) {
            return ReaderRejection::notFound();
        }

        $domain = $this->context->acrossAllOrganisations(
            static fn (): ?Domain => Domain::query()->whereKey($domainId)->first(),
        );

        if (! $domain instanceof Domain) {
            return ReaderRejection::notFound();
        }

        $snapshot = $this->snapshots->load($domain->host);

        if (! $snapshot->servable) {
            return ReaderRejection::notFound();
        }

        $match = $snapshot->matchFor($returnPath);

        if ($match === null) {
            return ReaderRejection::notFound();
        }

        $project = $match->mount->project;

        /*
         * 🛑 The binding is resolved through §8.12.3, not named by the reader.
         *
         * A `binding` parameter would be an open invitation: a reader could
         * point the flow at another project's provider and have DocUp conduct a
         * login against it. Which provider guards this project is a fact about
         * the project, so it is read from the project.
         */
        $binding = null;

        foreach ($this->bindings->contextsFor($project->id, $project->organisationId, $project->authzEpoch) as $candidate) {
            if ($candidate->type === 'oidc' && $candidate->isUsable()) {
                $binding = $candidate;
                break;
            }
        }

        if ($binding === null) {
            return ReaderRejection::notFound();
        }

        $issuer = $binding->string('issuer');
        $clientId = $binding->string('client_id');

        if ($issuer === null || $clientId === null) {
            return ReaderRejection::notFound();
        }

        try {
            $metadata = $this->discovery->metadataFor($binding->id, $issuer);

            $opened = $this->exchange->open(
                organisationId: (string) $domain->organisation_id,
                bindingId: $binding->id,
                domainId: $domainId,
                projectId: $project->id,
                handoffChallenge: $challenge,
                returnPath: $returnPath,
            );

            $url = AuthorisationRequest::url(
                metadata: $metadata,
                clientId: $clientId,
                redirectUri: AuthorisationRequest::callbackUrl(),
                state: $opened['state'],
                nonce: $opened['nonce'],
                verifier: $opened['verifier'],
                /*
                 * The binding's group scope, or no extra scope. Written as a
                 * conditional rather than a filtered array because the array
                 * form is already a list and the analyser says so.
                 */
                extraScopes: ($scope = $binding->string('groups_scope')) === null ? [] : [$scope],
            );
        } catch (OidcRefused $refused) {
            /*
             * 🛑 §8.22's chain gets the reason and the reader gets §8.12.23's
             * default. A misconfigured issuer is an operator's problem, and the
             * reader learning which part of it failed tells them about the
             * installation's internals.
             */
            OidcAudit::refused($refused, $binding, (string) $domain->organisation_id);

            return ReaderRejection::notFound();
        }

        return (new RedirectResponse($url))->withHeaders([
            /*
             * 🛑 `no-store`, because the URL carries a one-use `state` and a
             * `nonce`. A cached 302 would send a second reader into the first
             * one's exchange — which the single-use latch would refuse, so the
             * failure is a confusing login rather than a breach, but it is
             * still a redirect nobody should be able to replay.
             */
            'Cache-Control' => 'private, no-store',
            'Referrer-Policy' => 'no-referrer',
            'X-Robots-Tag' => 'noindex, nofollow',
        ]);
    }
}
