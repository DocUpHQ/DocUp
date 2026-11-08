<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Drivers;

use App\Access\AccessLeaf;
use App\Auth\Providers\AttemptResult;
use App\Auth\Providers\AuthComponent;
use App\Auth\Providers\BindingContext;
use App\Auth\Providers\BindingRefused;
use App\Auth\Providers\BindingRejection;
use App\Auth\Providers\Federation\ProvisioningMode;
use App\Auth\Providers\Oidc\AuthorisationRequest;
use App\Auth\Providers\Oidc\Discovery;
use App\Auth\Providers\Oidc\IdTokenVerifier;
use App\Auth\Providers\Oidc\JwksStore;
use App\Auth\Providers\Oidc\OidcRefused;
use App\Auth\Providers\ProbeResult;
use App\Auth\Providers\ReaderPresentation;

/**
 * §8.12.17's `oidc`: a reader an identity provider vouched for.
 *
 * 🛑 **This driver conducts no protocol.** That is the shape §8.12.18 asks for
 * — "protocol validation MUST be framework-enforced, not driver-optional" — and
 * it is worth being explicit about what it means here, because the obvious
 * design is the opposite one.
 *
 * The obvious design has the driver own the exchange: build the authorisation
 * URL, call the token endpoint, verify the id_token. A third-party driver
 * written to that shape would own its own validation, and the first one written
 * by somebody in a hurry would skip PKCE. So the exchange lives in
 * `App\Auth\Providers\Oidc` behind classes with no options
 * ({@see AuthorisationRequest},
 * {@see IdTokenVerifier}), the controllers drive them, and by the time this
 * driver is consulted the reader already holds a session.
 *
 * What is left for the driver is the part that **is** per-binding: whether this
 * reader's session was established through *this* binding.
 *
 * ## 🛑 Why `attempt()` reads a session rather than a credential
 *
 * An OIDC reader presents nothing on a documentation request. §8.12.10's
 * handoff gave them a per-origin session, and §8.12.11's grant carries the
 * decision — so by the time a documentation request arrives, the OIDC exchange
 * is minutes in the past and happened on another origin.
 *
 * So this driver is `portal_session`'s sibling with one difference that matters:
 * it is satisfied only when the session's reader identity belongs to **this**
 * binding. A project with a portal and an IdP can write one rule per audience,
 * and a dashboard member does not satisfy the IdP's rule — nor the reverse.
 */
final class OidcDriver implements AuthComponent
{
    public function __construct(
        private Discovery $discovery,
        private JwksStore $keys,
    ) {}

    public static function type(): string
    {
        return 'oidc';
    }

    public static function leaf(): AccessLeaf
    {
        return AccessLeaf::Binding;
    }

    public static function allowsProjectScope(): bool
    {
        /*
         * §8.12.17's table: `oidc` is `any` scope. §8.12.3's own example is
         * this driver — "one installation Okta binding serves 200 projects
         * while project 201 brings its own Entra tenant".
         */
        return true;
    }

    public static function mayMapDashboardRoles(): bool
    {
        /*
         * 🛑 True **as a driver capability**, and §8.12.5 is careful about what
         * that does and does not permit:
         *
         * > "Dashboard single sign-on is in scope at **installation and
         * > organisation scope only** … Project-scoped bindings MUST NOT
         * > produce any dashboard role, enforced both as a driver capability
         * > flag and as a validation invariant on group mappings."
         *
         * So the flag says "this driver *can* map roles"; the **scope** check
         * is what says whether this binding may. Both are required and they
         * answer different questions —
         * {@see \App\Auth\Providers\Federation\GroupMappings::add()} refuses the
         * project case, a database CHECK refuses it again, and
         * {@see \App\Auth\Providers\Federation\ReaderProvisioning} refuses it a
         * fourth time at login for rows that predate the others.
         *
         * Returning false here would be simpler and wrong: it would make
         * installation-wide SSO impossible, which §8.12.5 puts in scope.
         */
        return true;
    }

    /**
     * 🛑 Validate and **normalise**, refusing rather than correcting.
     *
     * The interface's contract, and the first version of this method got it
     * wrong: it returned a list of problems, which would have been a driver
     * reporting its own configuration errors as data for somebody else to
     * interpret. {@see AuthComponent::validate()} says "refusing rather than
     * correcting" and returns the config to store — so a bad config throws
     * with a reason, and the caller never has to decide what a non-empty return
     * meant.
     *
     * @param  array<string, mixed>  $config
     * @return array<string, mixed> the normalised config to store
     *
     * @throws BindingRefused
     */
    public function validate(array $config): array
    {
        $issuer = $config['issuer'] ?? null;

        if (! is_string($issuer) || $issuer === '') {
            throw BindingRefused::of(BindingRejection::ConfigInvalid, 'oidc needs an `issuer`');
        }

        $parts = parse_url($issuer);

        /*
         * 🛑 An absolute HTTPS URL with no query and no fragment. The issuer
         * is compared byte-for-byte against the token's `iss` (§8.12.18's
         * "exact `iss`") and is the prefix the discovery URL is built from — so
         * anything extra would make one of those two wrong.
         */
        if ($parts === false || ($parts['scheme'] ?? '') !== 'https' || ($parts['host'] ?? '') === '') {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '`issuer` must be an absolute https URL',
            );
        }

        if (isset($parts['query']) || isset($parts['fragment'])) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '`issuer` must carry no query string or fragment',
            );
        }

        if (str_ends_with($issuer, '/')) {
            /*
             * 🛑 Refused rather than trimmed, which is what "refusing rather
             * than correcting" means here. OIDC Discovery §4.3 requires the
             * document's `issuer` to equal the configured one **exactly**, so a
             * silent trim would store a value that differs from what the
             * operator typed — and the one screen where they could check their
             * own configuration would be showing them something else.
             */
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '`issuer` must not end in a slash; it is compared exactly',
            );
        }

        $clientId = $config['client_id'] ?? null;

        if (! is_string($clientId) || $clientId === '') {
            throw BindingRefused::of(BindingRejection::ConfigInvalid, 'oidc needs a `client_id`');
        }

        $normalised = [
            'issuer' => $issuer,
            'client_id' => $clientId,
        ];

        $mode = $config['provisioning'] ?? null;

        if ($mode !== null) {
            if (! is_string($mode) || ProvisioningMode::tryFrom($mode) === null) {
                throw BindingRefused::of(
                    BindingRejection::ConfigInvalid,
                    '`provisioning` must be disabled, create_reader or create_reader_and_map_groups',
                );
            }

            $normalised['provisioning'] = $mode;
        }

        $groupsClaim = $config['groups_claim'] ?? null;

        if ($groupsClaim !== null) {
            /*
             * The claim's **name**, which is a provider decision: Keycloak
             * sends `groups`, Entra sends `roles`. A JSON member name, so the
             * grammar is deliberately narrow — a claim name DocUp cannot look
             * up as an array key is a claim name that would silently match
             * nothing.
             */
            if (! is_string($groupsClaim) || preg_match('/^[A-Za-z0-9_.:\/-]{1,64}$/', $groupsClaim) !== 1) {
                throw BindingRefused::of(
                    BindingRejection::ConfigInvalid,
                    '`groups_claim` must be 1-64 characters of a JSON member name',
                );
            }

            $normalised['groups_claim'] = $groupsClaim;
        }

        $scope = $config['groups_scope'] ?? null;

        if ($scope !== null) {
            /*
             * 🛑 One scope token, and the grammar is RFC 6749 §3.3's. Several
             * scopes would be harmless in themselves — but this value is
             * interpolated into a URL DocUp builds, and a value that may
             * contain a space is a value that may contain anything.
             */
            if (! is_string($scope) || preg_match('/^[A-Za-z0-9_.:\/-]{1,64}$/', $scope) !== 1) {
                throw BindingRefused::of(
                    BindingRejection::ConfigInvalid,
                    '`groups_scope` must be one scope token of 1-64 unreserved characters',
                );
            }

            $normalised['groups_scope'] = $scope;
        }

        /*
         * 🛑 Only the known keys are returned, so an unknown one is dropped
         * rather than stored. §8.14.1 makes the same choice for theme tokens
         * ("unknown keys rejected") and the argument is the same: a config key
         * nothing reads is a key an operator believes is doing something.
         */
        return $normalised;
    }

    public function probe(BindingContext $binding): ProbeResult
    {
        $issuer = $binding->string('issuer');
        $clientId = $binding->string('client_id');

        if ($issuer === null || $clientId === null) {
            return ProbeResult::fail('the binding has no issuer or client id, so it would deny everybody');
        }

        /*
         * 🛑 The probe **fetches**, which is the point: §8.12.19's automated
         * half answers "could this provider work", and the only honest answer
         * comes from asking the provider. A probe that validated the stored
         * config and stopped would pass for an issuer that does not resolve.
         */
        try {
            $metadata = $this->discovery->refresh($binding->id, $issuer);
        } catch (OidcRefused $refused) {
            return ProbeResult::fail(
                'discovery failed: '.$refused->rejection->value,
                ['issuer' => $issuer],
            );
        }

        try {
            $kids = $this->keys->refresh($binding->id, $metadata->jwksUri);
        } catch (OidcRefused $refused) {
            return ProbeResult::fail(
                'the key set is unusable: '.$refused->rejection->value,
                ['jwks_uri' => $metadata->jwksUri],
            );
        }

        if ($kids === []) {
            return ProbeResult::fail('the provider publishes no key DocUp can verify with');
        }

        /*
         * 🛑 A secret is **not** required, and the probe says which mode this
         * is. A public client doing PKCE is a legitimate configuration — RFC
         * 9700 §2.1.1 prefers it for clients that cannot keep a secret — so
         * requiring one would refuse a correct setup. Saying so in the summary
         * is how an operator notices they meant to configure a confidential
         * client and did not.
         */
        $confidential = $binding->secret('client_secret') !== null;

        return ProbeResult::pass(
            'discovery and '.count($kids).' signing key(s) reachable; '
            .($confidential ? 'confidential client' : 'public client (PKCE only)'),
            [
                'issuer' => $metadata->issuer,
                'algorithms' => implode(',', $metadata->algorithms),
            ],
        );
    }

    public function attempt(BindingContext $binding, ReaderPresentation $presented): AttemptResult
    {
        $subject = $presented->sessionSubject;

        /*
         * 🛑 Satisfied only when the session was established through **this**
         * binding. `sessionBinding` is the binding that vouched for the
         * session's reader identity, or null for a dashboard member's session —
         * so a member does not satisfy an IdP rule, and a reader vouched for by
         * provider A does not satisfy a rule naming provider B.
         *
         * Compared with `hash_equals` because both sides are raw 16 bytes and
         * the comparison decides access; `===` would be correct here and this
         * costs nothing, which is the standing argument for using it on
         * anything credential-adjacent.
         */
        if ($subject === null || $presented->sessionBinding === null) {
            return AttemptResult::unsatisfied();
        }

        if (! hash_equals($binding->id, $presented->sessionBinding)) {
            return AttemptResult::unsatisfied();
        }

        /*
         * 🛑 No scope. §12.3's last conjunct narrows for `{share}` and
         * `{bearer}`, which are credentials with a stated reach. An
         * IdP-authenticated reader is admitted by whatever the rule says —
         * their groups shape *which* rules match, not how far one reaches.
         */
        return AttemptResult::satisfiedBy(AccessLeaf::Binding, subject: $subject);
    }
}
