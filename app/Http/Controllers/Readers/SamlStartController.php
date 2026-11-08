<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Readers;

use App\Auth\OrganisationContext;
use App\Auth\Providers\Bindings;
use App\Auth\Providers\Saml\AuthnRequest;
use App\Auth\Providers\Saml\SamlAudit;
use App\Auth\Providers\Saml\SamlExchange;
use App\Auth\Providers\Saml\SamlRefused;
use App\Models\Domain;
use App\Readers\ReaderHandoff;
use App\Readers\ReaderRejection;
use App\Serving\RoutingSnapshotLoader;
use App\Support\Uuid;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * §8.12.18's `<AuthnRequest>`: the dashboard half of a SAML login.
 *
 * 🛑 **Unauthenticated**, for the reason {@see OidcStartController} is: §8.12.1
 * keeps `users` and `reader_identities` "physically disjoint", so a reader whose
 * identity provider vouches for them never holds a dashboard session and a
 * route behind `auth` could not serve them. What stands in for `auth` is a
 * **verified domain** and an **active binding**, both resolved server-side from
 * the project rather than from a parameter.
 *
 * 🛑 **On the dashboard origin**, because ADR 0013 measured for SAML what
 * ADR 0008 measured for OIDC: one fixed `AssertionConsumerServiceURL` served
 * readers arriving from two different custom domains, and an unregistered one
 * was refused with HTTP 400 and no redirect. The control is what makes that
 * mean something — a provider that merely ignored the parameter would also have
 * passed the two success cases.
 *
 * ## What travels, and what does not
 *
 * The reader brings a `domain`, a `challenge` and a `return`, none trusted as
 * given — the same three {@see OidcStartController} takes, checked the same
 * way. Everything else DocUp generates: the request `ID` and the `RelayState`.
 *
 * 🛑 **And the originating domain does not travel in `RelayState`.** It would
 * fit, the SAML profile would return it unmodified, and ADR 0013 confirmed as
 * much — which is exactly the trap. `RelayState` comes back through the
 * browser, so a domain read out of it would be a reader-chosen return address.
 * The domain is stored in the exchange row and read from there; `RelayState` is
 * only ever an index.
 */
final readonly class SamlStartController
{
    public function __construct(
        private RoutingSnapshotLoader $snapshots,
        private Bindings $bindings,
        private SamlExchange $exchange,
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
         * 🛑 Checked here as well as by `ReaderHandoff::mint()`, because a
         * malformed challenge would be stored now and refused at the far end of
         * a full round trip through an identity provider — which the reader
         * experiences as "signing in does not work" with nothing to go on.
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
         * A `binding` parameter would let a reader point the flow at another
         * project's provider and have DocUp conduct a login against it. Which
         * provider guards this project is a fact about the project.
         */
        $binding = null;

        foreach ($this->bindings->contextsFor($project->id, $project->organisationId, $project->authzEpoch) as $candidate) {
            if ($candidate->type === 'saml' && $candidate->isUsable()) {
                $binding = $candidate;
                break;
            }
        }

        if ($binding === null) {
            return ReaderRejection::notFound();
        }

        $sso = $binding->string('sso_url');

        if ($sso === null) {
            return ReaderRejection::notFound();
        }

        try {
            $built = AuthnRequest::build(
                destination: $sso,
                issuer: AuthnRequest::entityId(),
                acs: AuthnRequest::acsUrl(),
            );

            $relayState = $this->exchange->open(
                organisationId: (string) $domain->organisation_id,
                bindingId: $binding->id,
                domainId: $domainId,
                projectId: $project->id,
                requestId: $built['id'],
                handoffChallenge: $challenge,
                returnPath: $returnPath,
            );

            $url = AuthnRequest::redirectUrl($sso, $built['xml'], $relayState);
        } catch (SamlRefused $refused) {
            /*
             * 🛑 §8.22's chain gets the reason and the reader gets §8.12.23's
             * default. A dashboard origin that is not configured is an
             * operator's problem, and the reader learning which part of it
             * failed tells them about the installation's internals.
             */
            SamlAudit::refused($refused, $binding, (string) $domain->organisation_id);

            return ReaderRejection::notFound();
        }

        return (new RedirectResponse($url))->withHeaders([
            /*
             * 🛑 `no-store`, because the URL carries a one-use `RelayState`. A
             * cached 302 would send a second reader into the first one's
             * exchange — which the single-use latch refuses, so the failure is
             * a confusing login rather than a breach, but it is still a
             * redirect nobody should be able to replay.
             */
            'Cache-Control' => 'private, no-store',
            'Referrer-Policy' => 'no-referrer',
            'X-Robots-Tag' => 'noindex, nofollow',
        ]);
    }
}
