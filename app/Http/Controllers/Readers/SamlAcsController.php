<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Readers;

use App\Auth\OrganisationContext;
use App\Auth\Providers\Bindings;
use App\Auth\Providers\Federation\ProvisioningMode;
use App\Auth\Providers\Federation\ProvisioningRefused;
use App\Auth\Providers\Federation\ProvisioningRejection;
use App\Auth\Providers\Federation\ReaderProvisioning;
use App\Auth\Providers\Saml\AuthnRequest;
use App\Auth\Providers\Saml\ResponseValidator;
use App\Auth\Providers\Saml\SamlAudit;
use App\Auth\Providers\Saml\SamlExchange;
use App\Auth\Providers\Saml\SamlRefused;
use App\Auth\Providers\Saml\SamlRejection;
use App\Models\Domain;
use App\Models\Project;
use App\Readers\HandoffRefused;
use App\Readers\ReaderHandoff;
use App\Readers\ReaderRejection;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * §8.12.18's assertion consumer service: where a SAML response is judged.
 *
 * 🛑 **The one fixed ACS URL** (ADR 0013), on the dashboard origin,
 * unauthenticated for the reason {@see SamlStartController} is.
 *
 * ## 🛑 The order of operations is the security property
 *
 * 1. **`RelayState` is consumed first**, atomically. That is the single-use
 *    latch, and doing it first means a replayed POST costs one indexed read and
 *    no XML parsing — so a replay is not a way to make DocUp do work.
 * 2. **The binding, domain and project come from the stored row**, never from
 *    the POST. The only things the reader brings are `SAMLResponse` and
 *    `RelayState`, and `RelayState` is an index.
 * 3. **The response is validated** by {@see ResponseValidator}, which has no
 *    options: both signatures, `Destination`, `InResponseTo`, `Audience`, the
 *    validity window, the subject, and the assertion-id replay cache last
 *    because it writes.
 * 4. **Only then** is a reader identity provisioned and a handoff code minted.
 *
 * ## 🛑 Why this route is exempt from CSRF, and why that is not a hole
 *
 * A SAML response arrives as a **cross-origin form POST** the identity provider
 * auto-submits, so there is no DocUp-issued token to present and no DocUp
 * session cookie in the request. Laravel's CSRF check would refuse every
 * genuine login, so the route opts out — and the thing that replaces it is
 * stronger than a token:
 *
 * - the POST must carry a `RelayState` naming an exchange **DocUp itself
 *   opened**, single-use and expiring in ten minutes;
 * - the response must be signed twice by the binding's configured certificate;
 * - its `InResponseTo` must be the request id stored in that exchange row.
 *
 * A forged POST fails the first check, and a captured genuine one fails the
 * first *or* the replay cache. §8.12.18's `InResponseTo` requirement is
 * precisely the anti-forgery control a CSRF token would have been, with the
 * identity provider's signature standing in for DocUp's.
 */
final readonly class SamlAcsController
{
    public function __construct(
        private Bindings $bindings,
        private SamlExchange $exchange,
        private ResponseValidator $validator,
        private ReaderProvisioning $provisioning,
        private ReaderHandoff $handoff,
        private OrganisationContext $context,
    ) {}

    public function __invoke(Request $request): Response
    {
        $relayState = (string) $request->input('RelayState', '');
        $encoded = (string) $request->input('SAMLResponse', '');

        if ($relayState === '' || $encoded === '') {
            /*
             * 🛑 A plain 404 with **no audit event**. A POST missing either
             * field is a crawler, a stale bookmark or a provider misconfigured
             * to use HTTP-Redirect for the response — none of them a security
             * event, and an operator reading a burst of `saml.*.refused` needs
             * them all to mean something went wrong.
             */
            return ReaderRejection::notFound();
        }

        /*
         * 🛑 Decoded here rather than inside the validator, so `SafeXml`'s size
         * ceiling applies to the **XML** rather than to its base64 armour — and
         * so a response that is not even base64 is refused before a parser
         * exists. `strict` mode, because a lax decode would silently drop
         * characters and hand the signature verifier a different document from
         * the one the identity provider signed.
         */
        $xml = base64_decode($encoded, true);

        if ($xml === false || $xml === '') {
            SamlAudit::refused(
                SamlRefused::of(SamlRejection::ResponseMalformed, 'the SAMLResponse is not base64'),
                null,
                null,
            );

            return ReaderRejection::notFound();
        }

        try {
            /* 1. Consume the relay state. Nothing before this, nothing twice. */
            $exchange = $this->exchange->consume($relayState);
        } catch (SamlRefused $refused) {
            SamlAudit::refused($refused, null, null);

            return ReaderRejection::notFound();
        }

        $binding = $this->context->acrossAllOrganisations(
            fn () => $this->bindings->byId($exchange['binding_id']),
        );

        if ($binding === null || ! $binding->isUsable()) {
            /*
             * The binding was active when the flow started and is not now —
             * degraded by a failed probe, or disabled by an operator. §8.12.19
             * makes a non-active binding deny, and a login completed against
             * one would admit a reader on the word of a provider the
             * installation has stopped trusting.
             */
            SamlAudit::refused(
                SamlRefused::of(SamlRejection::ConfigInvalid, 'the binding is no longer active'),
                $binding,
                $exchange['organisation_id'],
            );

            return ReaderRejection::notFound();
        }

        $certificate = $binding->string('certificate');
        $issuer = $binding->string('idp_entity_id');

        if ($certificate === null || $issuer === null) {
            SamlAudit::refused(
                SamlRefused::of(
                    SamlRejection::ConfigInvalid,
                    'the binding has no signing certificate or no identity provider',
                ),
                $binding,
                $exchange['organisation_id'],
            );

            return ReaderRejection::notFound();
        }

        try {
            /*
             * 3. 🛑 Everything §8.12.18 requires, in one call with no options.
             *
             * `inResponseTo` comes from the stored row, so an IdP-initiated
             * response — which carries none — cannot match, which is how
             * §8.12.18's "off by default" is enforced without a flag.
             */
            $verified = $this->validator->validate(
                xml: $xml,
                certificate: $certificate,
                issuer: $issuer,
                audience: AuthnRequest::entityId(),
                destination: AuthnRequest::acsUrl(),
                inResponseTo: $exchange['in_response_to'],
            );

            /*
             * 4. 🛑 Provision through the **shared** §8.13.7 implementation,
             * given the assertion's verified facts in the flat shape it takes.
             *
             * `sub` is the `NameID`, which §8.12.1 requires: reader identities
             * are keyed `(binding_id, subject_hash)` and "email MUST NEVER be
             * used for linking or lookup" — which is why
             * {@see AuthnRequest::NAMEID_PERSISTENT} asks for a persistent
             * identifier and nothing here looks at an email attribute.
             */
            $identity = $this->provisioning->provision(
                binding: $binding,
                mode: ProvisioningMode::fromConfig($binding->string('provisioning')),
                claims: $this->factsFrom($verified),
                groupsClaim: $binding->string('groups_attribute') ?? 'groups',
            );
        } catch (ProvisioningRefused $refused) {
            SamlAudit::refused($this->asSaml($refused), $binding, $exchange['organisation_id']);

            return ReaderRejection::notFound();
        } catch (SamlRefused $refused) {
            /*
             * 🛑 The row stays consumed, and there is deliberately no way to
             * release it. The whole point of the latch is that a captured
             * assertion gets exactly one try — and a retry could not succeed
             * anyway, because by the time anything here can fail the validator
             * has written the assertion id to the replay cache.
             * `SamlExchange::MAX_ATTEMPTS` carries the full reasoning and the
             * asymmetry with OIDC, which does have a releasable leg.
             */
            SamlAudit::refused($refused, $binding, $exchange['organisation_id']);

            return ReaderRejection::notFound();
        }

        [$domain, $project] = $this->context->acrossAllOrganisations(
            static fn (): array => [
                Domain::query()->whereKey($exchange['domain_id'])->first(),
                Project::query()->whereKey($exchange['project_id'])->first(),
            ],
        );

        if (! $domain instanceof Domain || ! $project instanceof Project) {
            return ReaderRejection::notFound();
        }

        try {
            /*
             * 🛑 §8.12.10's handoff code, for the identity rather than a user.
             * The challenge is the one the documentation origin stored in its
             * own `__Host-` cookie, so the code is redeemable only by the
             * browser that began the flow — which is what makes this redirect
             * safe to put in a URL.
             */
            $minted = $this->handoff->mint(
                subject: $identity,
                domain: $domain,
                project: $project,
                challenge: $exchange['handoff_challenge'],
                returnPath: $exchange['return_path'],
            );
        } catch (HandoffRefused) {
            return ReaderRejection::notFound();
        }

        SamlAudit::succeeded($binding, $identity->id);

        return (new RedirectResponse($minted['url']))->withHeaders([
            'Cache-Control' => 'private, no-store',
            'Referrer-Policy' => 'no-referrer',
            'X-Robots-Tag' => 'noindex, nofollow',
        ]);
    }

    /**
     * The assertion's verified facts, flattened into the shape §8.13.7 takes.
     *
     * 🛑 **`sub` is the `NameID` and nothing else may become it.** §8.12.1:
     * reader identities are keyed `(binding_id, subject_hash)` and "email MUST
     * NEVER be used for linking or lookup". A provider that sends no usable
     * `NameID` has already been refused by the validator, so this is a
     * narrowing rather than a fallback — there is deliberately no "use the
     * email attribute instead" branch, because that branch is the requirement's
     * violation.
     *
     * 🛑 **A multi-valued attribute keeps its list; a single-valued one is
     * flattened.** SAML attributes are always lists; OIDC claims are not. The
     * groups attribute has to arrive as a list for
     * `GroupMappings::assertedGroups()` to read it, and a display name has to
     * arrive as a string for `ReaderSubject::displayLabel()` to use it — so the
     * arity is decided by how many values the provider actually sent, which is
     * the only rule that needs no per-attribute configuration.
     *
     * @param  array{id: string, subject: string, attributes: array<string, list<string>>}  $verified
     * @return array<string, mixed>
     */
    private function factsFrom(array $verified): array
    {
        $facts = ['sub' => $verified['subject']];

        foreach ($verified['attributes'] as $name => $values) {
            if ($name === 'sub') {
                /*
                 * 🛑 An attribute literally named `sub` must not overwrite the
                 * `NameID`. It would take a deliberately hostile provider
                 * configuration, and the cost of the check is one comparison —
                 * but the consequence would be a reader choosing their own
                 * identity key, which is the worst outcome in this file.
                 */
                continue;
            }

            $facts[$name] = count($values) === 1 ? $values[0] : $values;
        }

        return $facts;
    }

    /**
     * 🛑 Provisioning's protocol-free refusal, in SAML's words.
     *
     * §17 requires each failure to raise a distinct audit event, and an
     * operator triaging a SAML problem filters for `saml.*` — so a shared
     * `federation.*` action reaching the chain would be a refusal they never
     * see. The mapping is total by construction: every case
     * `ProvisioningRejection` can *throw* is named, and the compiler notices
     * when a fourth is added.
     *
     * `DashboardRoleNotPermitted` is absent on purpose — it is audited inside
     * the reconciliation and never thrown, because §8.12.5's fourth enforcement
     * skips the mapping rather than refusing the reader.
     */
    private function asSaml(ProvisioningRefused $refused): SamlRefused
    {
        $rejection = match ($refused->rejection) {
            ProvisioningRejection::SubjectMissing => SamlRejection::SubjectMissing,
            ProvisioningRejection::ProvisioningDisabled,
            ProvisioningRejection::DashboardRoleNotPermitted => SamlRejection::ProvisioningDisabled,
        };

        return SamlRefused::of($rejection, $refused->getMessage());
    }
}
