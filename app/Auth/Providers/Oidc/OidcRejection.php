<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Oidc;

/**
 * 🛑 Every way an OIDC exchange can be refused, each a stable identifier.
 *
 * §17's Phase 24 exit criteria name seven by hand:
 *
 * > "Omitted PKCE, a reused `nonce`, a wrong `iss`, a wrong `aud`, `alg: none`,
 * > a missing `at_hash` and an unpinned `kid` are each rejected with **distinct
 * > audit events**."
 *
 * 🛑 **Distinct is the requirement, and it is why this is an enum rather than a
 * message.** A single `oidc.login.failed` event would satisfy "rejected" and
 * fail the criterion: an operator reading the audit chain has to be able to
 * tell "our IdP is misconfigured and sends no `at_hash`" from "somebody is
 * replaying a `nonce` at us", because the first is a support ticket and the
 * second is an attack. One vocabulary, one case per cause, and the case is
 * what reaches §8.22's chain.
 *
 * 🛑 **None of these values ever reaches a reader.** §8.12.23 makes the
 * response to a failed login the project's `deny_status` with no detail; the
 * reason goes to the audit chain, where the operator can see it and the
 * attacker cannot. That split is the whole point of recording a reason at all:
 * it is for the person who can fix it.
 *
 * The enum is also deliberately *not* ordered by severity. A caller that
 * branched on severity would be making a judgement the audit reader should
 * make, with less information.
 */
enum OidcRejection: string
{
    // ---------------------------------------- §8.12.18's seven named by §17

    /**
     * 🛑 The authorisation request carried no PKCE challenge, or carried one
     * that was not S256.
     *
     * §8.12.18: "PKCE S256 mandatory". Mandatory means DocUp refuses to *send*
     * a request without it, so reaching this case means something assembled an
     * authorisation URL outside {@see AuthorisationRequest} — which is the
     * condition the architecture test exists to prevent, caught at runtime as
     * well.
     */
    case PkceMissing = 'oidc.pkce_missing';

    /**
     * 🛑 A `nonce` presented twice.
     *
     * §8.12.18: "single-use `nonce`". The second presentation is either a
     * replayed id_token or a reader double-clicking; the row's `consumed_at`
     * latch cannot tell, and refusing both is correct because an id_token is
     * not idempotent — it mints a session.
     */
    case NonceReplayed = 'oidc.nonce_replayed';

    /** The token's `nonce` claim is not the one this exchange asked for. */
    case NonceMismatch = 'oidc.nonce_mismatch';

    /**
     * 🛑 `iss` is not **exactly** the issuer this binding is configured for.
     *
     * §8.12.18: "exact `iss`". Exact, not prefix and not host-suffix: an
     * issuer comparison that accepted `https://idp.example.com.attacker.test`
     * because it contained the configured host is the classic mix-up attack,
     * and RFC 9700 §4.4 names it.
     */
    case IssuerMismatch = 'oidc.issuer_mismatch';

    /**
     * 🛑 `aud` does not contain this binding's `client_id`, or `azp` disagrees
     * with it where several audiences are present.
     *
     * §8.12.18: "exact `aud`". A token minted for another client at the same
     * IdP is a valid token; accepting it is how one tenant's reader becomes
     * another's.
     */
    case AudienceMismatch = 'oidc.audience_mismatch';

    /**
     * 🛑 The token's header names an algorithm outside the allowlist — `none`
     * most of all.
     *
     * §8.12.18: "a signing-algorithm allowlist excluding `none`". The reason
     * this is a *case* and not an impossibility is that the check is worth
     * auditing: a token arriving with `alg: none` is not a misconfiguration,
     * it is somebody trying.
     */
    case AlgorithmNotAllowed = 'oidc.algorithm_not_allowed';

    /**
     * 🛑 `at_hash` is absent or does not match the access token.
     *
     * §8.12.18 requires it. It binds the id_token to the access token that
     * arrived with it, so a token pair cannot be assembled from two different
     * exchanges.
     */
    case AtHashInvalid = 'oidc.at_hash_invalid';

    /**
     * 🛑 The token's `kid` is not in the pinned key set, and the refresh floor
     * forbids fetching again yet.
     *
     * §8.12.18: "JWKS pinned by `kid` with a bounded refresh floor". The floor
     * is the interesting half: without it, an unknown `kid` is a free outbound
     * request, so an attacker with a token generator has a DoS against the
     * IdP and against DocUp's own egress budget.
     */
    case KeyNotPinned = 'oidc.key_not_pinned';

    // ----------------------------------------------------- the rest of §8.12.18

    /** The `state` parameter resolves to no in-flight authorisation request. */
    case StateUnknown = 'oidc.state_unknown';

    /** The in-flight request has already been consumed, or has expired. */
    case StateExpired = 'oidc.state_expired';

    /**
     * 🛑 The IdP sent an implicit-flow response — a token in the fragment, or
     * an `id_token` where a `code` was asked for.
     *
     * §8.12.18: "no implicit flow". DocUp never requests one, so this is a
     * provider configured against the specification or a forged redirect.
     */
    case ImplicitFlowRefused = 'oidc.implicit_flow_refused';

    /** The signature does not verify under the pinned key. */
    case SignatureInvalid = 'oidc.signature_invalid';

    /** `exp` is past, or `iat`/`nbf` is in the future beyond the allowed skew. */
    case TokenExpired = 'oidc.token_expired';

    /** The token is not a JWS at all, or its claim set is not an object. */
    case TokenMalformed = 'oidc.token_malformed';

    /** `sub` is absent or empty: §8.12.1 keys a reader identity on it. */
    case SubjectMissing = 'oidc.subject_missing';

    /** The token endpoint refused the exchange, or answered unusably. */
    case TokenEndpointFailed = 'oidc.token_endpoint_failed';

    /** The discovery document is absent, unparseable, or disagrees with itself. */
    case DiscoveryFailed = 'oidc.discovery_failed';

    /** The JWKS document is absent, unparseable, or holds no usable key. */
    case JwksFailed = 'oidc.jwks_failed';

    /**
     * 🛑 The binding's configuration is not usable — a missing `client_id`, an
     * issuer that is not an absolute HTTPS URL, a group mapping §8.12.5
     * forbids.
     */
    case ConfigInvalid = 'oidc.config_invalid';

    /**
     * 🛑 JIT provisioning is `disabled` and no reader identity exists for this
     * subject.
     *
     * §8.13.7's `disabled` mode is not a failure to provision — it is an
     * operator saying "only readers I have already created". Refusing is the
     * configured behaviour, and auditing it is how the operator discovers that
     * somebody who should have access does not.
     */
    case ProvisioningDisabled = 'oidc.provisioning_disabled';

    /**
     * 🛑 A project-scoped binding's mapping tried to produce a dashboard role.
     *
     * §8.12.5, and §17 makes it an exit criterion: "A project-scoped binding
     * attempting to map a dashboard role is rejected at validation **and** by
     * the driver capability flag." Refused at write time by
     * {@see GroupMappings}, by a database CHECK, and here at login — three
     * places, because the requirement says "enforced both as a driver
     * capability flag and as a validation invariant" and a login-time check is
     * what catches a row written before either existed.
     */
    case DashboardRoleNotPermitted = 'oidc.dashboard_role_not_permitted';

    /**
     * The audit action for this rejection.
     *
     * 🛑 One action per case, which is what "distinct audit events" means. The
     * value is already a dotted identifier in §8.22.5's style, so the action
     * **is** the case value — not a prefix plus a payload field, because a
     * payload field is not something an audit query can key on without knowing
     * to look for it.
     */
    public function auditAction(): string
    {
        return $this->value.'.refused';
    }
}
