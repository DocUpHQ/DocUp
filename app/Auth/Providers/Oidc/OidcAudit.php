<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Oidc;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\Providers\BindingContext;
use App\Support\Uuid;

/**
 * 🛑 §17's "each rejected with **distinct audit events**", in one place.
 *
 * One function, so that every refusal in the OIDC flow produces an event with
 * the *same shape* and a *different action*. Both halves matter:
 *
 * - **Different action** is the requirement. `OidcRejection::auditAction()`
 *   derives it from the case, so a new rejection cannot be added without
 *   getting its own event, and an operator can query for one cause.
 * - **Same shape** is what makes the events usable. An auditor correlating a
 *   burst of refusals needs the binding and the reason in the same fields every
 *   time; a per-call-site payload would give them seven schemas.
 *
 * 🛑 **Nothing here reaches the reader.** §8.12.23 makes a failed login the
 * project's `deny_status` with no body, and that is what the controllers
 * return. This is the other side of that split: the reason goes where the
 * person who can fix it will see it.
 *
 * 🛑 **And nothing provider-supplied reaches the chain.** §8.22.5 keeps free
 * text out, so there is no `error_description` field and no claim values — the
 * payload is identifiers and fixed vocabulary, which is what makes a chain
 * verifiable rather than a log.
 */
final readonly class OidcAudit
{
    /**
     * Record a refusal.
     *
     * @param  BindingContext|null  $binding  null where the failure happened
     *                                        before a binding was resolved —
     *                                        an unknown `state`, say
     */
    public static function refused(
        OidcRefused $refused,
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
            subjectType: $binding === null ? 'oidc_exchange' : 'auth_provider_binding',
            subjectId: $binding?->id,
            /*
             * The reason in its own field as well as in the action, because an
             * audit reader filtering on `reason_code` across providers should
             * find OIDC's refusals beside SAML's when Phase 25 adds them.
             */
            reasonCode: $refused->rejection->value,
            payload: [
                'driver' => 'oidc',
                'binding' => $binding === null ? 'unresolved' : Uuid::toText($binding->id),
            ],
        );
    }

    /** Record a successful login, so the chain holds both outcomes. */
    public static function succeeded(BindingContext $binding, string $readerIdentityId): void
    {
        Audit::record(
            action: 'oidc.login.succeeded',
            actorType: ActorType::System,
            organisationId: $binding->organisationId,
            subjectType: 'reader_identity',
            subjectId: $readerIdentityId,
            payload: [
                'driver' => 'oidc',
                'binding' => Uuid::toText($binding->id),
            ],
        );
    }
}
