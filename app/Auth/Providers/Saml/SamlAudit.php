<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Saml;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\Providers\BindingContext;
use App\Support\Uuid;

/**
 * 🛑 §17's "each rejected with **distinct audit events**", for SAML.
 *
 * `App\Auth\Providers\Oidc\OidcAudit`'s sibling, deliberately the same shape —
 * one action per cause, the same fields every time — because the two halves do
 * different work:
 *
 * - **Different action** is §17's Phase 25 exit criterion by name: "A stripped
 *   signature, a wrapped signature, a replayed assertion, a wrong audience, an
 *   expired `NotOnOrAfter`, a comment-truncation payload and an XXE payload are
 *   each rejected with distinct audit events." `SamlRejection::auditAction()`
 *   derives the action from the case, so a rejection cannot be added without
 *   getting its own event.
 * - **Same shape** is what makes them usable. An operator correlating a burst
 *   of refusals needs the binding and the reason in the same fields; a
 *   per-call-site payload would give them nineteen schemas.
 *
 * 🛑 **A separate class rather than a shared `ProviderAudit`.** The two differ
 * in exactly one way — the `driver` field and the fallback subject type — which
 * looks like an argument for merging them. It is not: the thing an operator
 * does with these events is filter by protocol, and a shared writer would be
 * one place where a future change silently applied to both vocabularies. The
 * duplication is eleven lines and the coupling it avoids is the audit chain's.
 *
 * 🛑 **Nothing here reaches the reader**, and **nothing the identity provider
 * said reaches the chain.** §8.12.23 makes a failed login the project's
 * `deny_status` with no body; §8.22.5 keeps free text out — and a SAML response
 * is a document somebody else wrote, so its `StatusMessage`, its attributes and
 * its `NameID` are all free text.
 */
final readonly class SamlAudit
{
    /**
     * Record a refusal.
     *
     * @param  BindingContext|null  $binding  null where the failure happened
     *                                        before a binding was resolved —
     *                                        an unknown `RelayState`, say
     */
    public static function refused(
        SamlRefused $refused,
        ?BindingContext $binding,
        ?string $organisationId,
    ): void {
        Audit::record(
            /* 🛑 One action per cause. §17's "distinct" lives here. */
            action: $refused->rejection->auditAction(),
            /*
             * `System`, not `User`: nobody is authenticated at the point a
             * login is refused, and §8.12.1 would forbid naming a reader
             * identity as an actor even if one were known.
             */
            actorType: ActorType::System,
            organisationId: $organisationId,
            subjectType: $binding === null ? 'saml_exchange' : 'auth_provider_binding',
            subjectId: $binding?->id,
            /*
             * The reason in its own field as well as in the action, so an
             * auditor filtering `reason_code` across providers finds SAML's
             * refusals beside OIDC's — which is what `OidcAudit` anticipated
             * when it said "when Phase 25 adds them".
             */
            reasonCode: $refused->rejection->value,
            payload: [
                'driver' => 'saml',
                'binding' => $binding === null ? 'unresolved' : Uuid::toText($binding->id),
            ],
        );
    }

    /** Record a successful login, so the chain holds both outcomes. */
    public static function succeeded(BindingContext $binding, string $readerIdentityId): void
    {
        Audit::record(
            action: 'saml.login.succeeded',
            actorType: ActorType::System,
            organisationId: $binding->organisationId,
            subjectType: 'reader_identity',
            subjectId: $readerIdentityId,
            payload: [
                'driver' => 'saml',
                'binding' => Uuid::toText($binding->id),
            ],
        );
    }
}
