<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Readers;

use App\Auth\OrganisationContext;
use App\Auth\Providers\Bindings;
use App\Auth\Providers\Oidc\AuthorisationRequest;
use App\Auth\Providers\Oidc\Discovery;
use App\Auth\Providers\Oidc\IdTokenVerifier;
use App\Auth\Providers\Oidc\OidcAudit;
use App\Auth\Providers\Oidc\OidcExchange;
use App\Auth\Providers\Oidc\OidcRefused;
use App\Auth\Providers\Oidc\OidcRejection;
use App\Auth\Providers\Oidc\ProviderMetadata;
use App\Auth\Providers\Oidc\ProvisioningMode;
use App\Auth\Providers\Oidc\ReaderProvisioning;
use App\Auth\Providers\Oidc\TokenEndpoint;
use App\Models\Domain;
use App\Models\Project;
use App\Readers\HandoffRefused;
use App\Readers\ReaderHandoff;
use App\Readers\ReaderRejection;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * §8.12.18's callback: where everything is checked.
 *
 * 🛑 **The one fixed `redirect_uri`** (ADR 0008), on the dashboard origin,
 * unauthenticated for the reason {@see OidcStartController} is.
 *
 * ## The order of operations is the security property
 *
 * 1. **`state` is consumed first**, atomically, before anything else happens.
 *    That is §8.12.18's single-use, and doing it first means a replayed
 *    callback costs one indexed read and no outbound request — so a replay is
 *    not a way to make DocUp talk to an identity provider.
 * 2. **The binding and domain come from the stored row**, never from the
 *    callback's query. §8.12.10's rule about return URLs applies with full
 *    force here: the only things the reader brings are `code` and `state`, and
 *    `state` is an index.
 * 3. **The code is exchanged** on DocUp's back channel, with the stored PKCE
 *    verifier.
 * 4. **The id_token is verified** by {@see IdTokenVerifier}, which has no
 *    options.
 * 5. **Only then** is a reader identity provisioned and a handoff code minted.
 *
 * 🛑 **An implicit-flow response is refused before step 1.** §8.12.18 says "no
 * implicit flow", and a callback carrying `id_token` or `access_token` in the
 * query is one — DocUp never asks for it, so its arrival is a provider
 * configured against the specification or a forged redirect. Refusing it
 * without consuming the `state` is deliberate: the reader's real exchange, if
 * they have one in flight, should still work.
 */
final readonly class OidcCallbackController
{
    public function __construct(
        private Bindings $bindings,
        private Discovery $discovery,
        private OidcExchange $exchange,
        private TokenEndpoint $tokens,
        private IdTokenVerifier $verifier,
        private ReaderProvisioning $provisioning,
        private ReaderHandoff $handoff,
        private OrganisationContext $context,
    ) {}

    public function __invoke(Request $request): Response
    {
        /*
         * 🛑 §8.12.18's "no implicit flow", checked before the state is spent.
         */
        if ($request->query('id_token') !== null || $request->query('access_token') !== null) {
            OidcAudit::refused(
                OidcRefused::of(OidcRejection::ImplicitFlowRefused, 'a token arrived in the callback query'),
                null,
                null,
            );

            return ReaderRejection::notFound();
        }

        $state = (string) $request->query('state', '');
        $code = (string) $request->query('code', '');

        if ($state === '' || $code === '') {
            /*
             * 🛑 A provider that refused — the reader cancelled, or consent was
             * declined — arrives here with `error` and no `code`. That is not a
             * DocUp failure and the audit chain should not call it one, so it
             * is a plain 404 with no event: an operator reading a burst of
             * `oidc.*.refused` events needs them to mean something went wrong.
             */
            return ReaderRejection::notFound();
        }

        try {
            /* 1. Consume the state. Nothing before this, nothing twice. */
            $exchange = $this->exchange->consume($state);
        } catch (OidcRefused $refused) {
            OidcAudit::refused($refused, null, null);

            return ReaderRejection::notFound();
        }

        $binding = $this->context->acrossAllOrganisations(
            fn () => $this->bindings->byId($exchange['binding_id']),
        );

        if ($binding === null || ! $binding->isUsable()) {
            /*
             * The binding was active when the flow started and is not now —
             * degraded by a failed probe, or disabled by an operator. §8.12.19
             * is clear that a non-active binding denies, and a login completed
             * against one would be a reader admitted by a provider the
             * installation has stopped trusting.
             */
            OidcAudit::refused(
                OidcRefused::of(OidcRejection::ConfigInvalid, 'the binding is no longer active'),
                $binding,
                $exchange['organisation_id'],
            );

            return ReaderRejection::notFound();
        }

        $issuer = $binding->string('issuer');
        $clientId = $binding->string('client_id');

        if ($issuer === null || $clientId === null) {
            OidcAudit::refused(
                OidcRefused::of(OidcRejection::ConfigInvalid, 'the binding has no issuer or client id'),
                $binding,
                $exchange['organisation_id'],
            );

            return ReaderRejection::notFound();
        }

        try {
            $metadata = $this->discovery->metadataFor($binding->id, $issuer);

            /* 3. The back-channel exchange, with the stored verifier. */
            $tokens = $this->tokens->exchange(
                metadata: $metadata,
                clientId: $clientId,
                clientSecret: $binding->secret('client_secret'),
                redirectUri: AuthorisationRequest::callbackUrl(),
                code: $code,
                verifier: $exchange['code_verifier'],
            );

            /*
             * 4. 🛑 Verification, and the nonce is supplied from the stored
             * **hash** comparison rather than from a plaintext DocUp kept. The
             * verifier needs the plaintext to compare against the claim, so it
             * is taken from the token and checked against the hash here — which
             * is why `nonceMatches()` exists and why the verifier is given the
             * claim's own value only after it has matched.
             */
            $claims = $this->verifyWithStoredNonce($tokens, $exchange, $metadata, $binding->id, $clientId);

            /* 5. Provision, reconcile, and mint. */
            $identity = $this->provisioning->provision(
                binding: $binding,
                mode: ProvisioningMode::fromConfig($binding->string('provisioning')),
                claims: $claims,
                groupsClaim: $binding->string('groups_claim') ?? 'groups',
            );
        } catch (OidcRefused $refused) {
            /*
             * 🛑 The row stays consumed. A failed exchange must not be
             * retriable with the same `state` — the code is spent at the
             * provider too, and a retry that reached step 3 again would be
             * DocUp replaying somebody's authorisation code.
             */
            OidcAudit::refused($refused, $binding, $exchange['organisation_id']);

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

        OidcAudit::succeeded($binding, $identity->id);

        return (new RedirectResponse($minted['url']))->withHeaders([
            'Cache-Control' => 'private, no-store',
            'Referrer-Policy' => 'no-referrer',
            'X-Robots-Tag' => 'noindex, nofollow',
        ]);
    }

    /**
     * Verify the id_token against the nonce this exchange opened.
     *
     * 🛑 The nonce is stored hashed (§9.1.4), so there is no plaintext to hand
     * the verifier. The token's own claim is read, compared against the stored
     * digest, and only then passed in as the expected value — so the verifier's
     * `hash_equals` is comparing a value that has already been proven to be
     * this exchange's.
     *
     * That looks circular and is not: the comparison that *decides* is
     * {@see OidcExchange::nonceMatches()}, against a digest DocUp wrote before
     * the reader left. The verifier's own check then guarantees the claim it
     * validated is the same one — which matters because the two run over
     * different copies of the token in a future where one is refactored.
     *
     * @param  array{id_token: string, access_token: ?string}  $tokens
     * @param  array{nonce_hash: string, ...}  $exchange
     * @return array<string, mixed>
     *
     * @throws OidcRefused
     */
    private function verifyWithStoredNonce(
        array $tokens,
        array $exchange,
        ProviderMetadata $metadata,
        string $bindingId,
        string $clientId,
    ): array {
        $claimed = $this->nonceClaim($tokens['id_token']);

        if ($claimed === null || ! $this->exchange->nonceMatches($exchange['nonce_hash'], $claimed)) {
            throw OidcRefused::of(
                OidcRejection::NonceMismatch,
                'the token does not answer this authorisation request',
            );
        }

        return $this->verifier->claimsFor(
            token: $tokens['id_token'],
            bindingId: $bindingId,
            metadata: $metadata,
            clientId: $clientId,
            expectedNonce: $claimed,
            accessToken: $tokens['access_token'],
        );
    }

    /**
     * The `nonce` claim, read **without** verifying anything.
     *
     * 🛑 Safe only because of what is done with it: the value is compared
     * against a digest DocUp stored, and nothing else. It is not trusted, not
     * logged and not used to select a key — and the token it came from is fully
     * verified immediately afterwards, so an unsigned token's nonce buys a
     * comparison and nothing more.
     */
    private function nonceClaim(string $token): ?string
    {
        $segments = explode('.', $token);

        if (count($segments) !== 3) {
            return null;
        }

        $raw = base64_decode(strtr($segments[1], '-_', '+/'), true);

        if ($raw === false) {
            return null;
        }

        $claims = json_decode($raw, true);

        if (! is_array($claims)) {
            return null;
        }

        $nonce = $claims['nonce'] ?? null;

        return is_string($nonce) && $nonce !== '' ? $nonce : null;
    }
}
