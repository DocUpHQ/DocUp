<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Ldap;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\Providers\BindingContext;
use App\Auth\Providers\Saml\SamlAudit;
use App\Support\Uuid;

/**
 * 🛑 §17's "each rejected with **distinct audit events**", for LDAP.
 *
 * {@see SamlAudit}'s sibling and the same shape, for
 * the reason stated there: an operator filters these by protocol, and a shared
 * writer would be one place where a change silently applied to three
 * vocabularies. {@see LdapRejection::auditAction()} derives the action from the
 * case, so a rejection cannot be added without getting its own event.
 *
 * 🛑 **This chain is the only place the distinction survives.** The sign-in
 * page tells a reader one sentence whatever happened — see
 * `LdapSignInController` in `App\Http\Controllers\Readers` — because a
 * message that separated "no such user" from "wrong password" would enumerate
 * the operator's employee directory. So an operator triaging a failed login
 * has nothing but these events, which is why the reason is in its own field as
 * well as in the action.
 *
 * 🛑 **And no username reaches the chain.** §8.22.5 keeps free text out, and a
 * username is text a reader typed: a chain that stored it would accumulate a
 * list of every name anybody has guessed at against the operator's directory,
 * in a table built to be read by auditors. The binding and the reason are
 * enough to see an attack; the addresses are in the request log, where a
 * retention policy already covers them.
 */
final readonly class LdapAudit
{
    /** Record a refusal, with its cause in both the action and the field. */
    public static function refused(LdapRefused $refused, BindingContext $binding): void
    {
        Audit::record(
            action: $refused->rejection->auditAction(),
            /*
             * `System`, not `User`: nobody is authenticated at the point a
             * login is refused, and §8.12.1 would forbid naming a reader
             * identity as an actor even if one were known.
             */
            actorType: ActorType::System,
            organisationId: $binding->organisationId,
            subjectType: 'auth_provider_binding',
            subjectId: $binding->id,
            reasonCode: $refused->rejection->value,
            payload: [
                'driver' => 'ldap',
                'binding' => Uuid::toText($binding->id),
            ],
        );
    }

    /**
     * Record a throttled attempt, which is not a refusal by the directory.
     *
     * 🛑 Its own action rather than `ldap.credentials_rejected`, because the
     * two mean opposite things to an operator: a burst of rejections is
     * somebody guessing, and a burst of *throttles* is the lockout working.
     * Collapsing them would hide the moment the limiter started carrying the
     * load.
     */
    public static function throttled(BindingContext $binding, int $secondsUntilRetry): void
    {
        Audit::record(
            action: 'ldap.login.throttled',
            actorType: ActorType::System,
            organisationId: $binding->organisationId,
            subjectType: 'auth_provider_binding',
            subjectId: $binding->id,
            reasonCode: 'ldap.throttled',
            payload: [
                'driver' => 'ldap',
                'binding' => Uuid::toText($binding->id),
                /*
                 * The operator's number, deliberately not the reader's.
                 * {@see \App\Auth\Providers\ReaderThrottle::secondsUntilRetry()}
                 * says why a `Retry-After` would confirm the credential exists.
                 */
                'retry_after' => (string) $secondsUntilRetry,
            ],
        );
    }

    /** Record a successful login, so the chain holds both outcomes. */
    public static function succeeded(BindingContext $binding, string $readerIdentityId): void
    {
        Audit::record(
            action: 'ldap.login.succeeded',
            actorType: ActorType::System,
            organisationId: $binding->organisationId,
            subjectType: 'reader_identity',
            subjectId: $readerIdentityId,
            payload: [
                'driver' => 'ldap',
                'binding' => Uuid::toText($binding->id),
            ],
        );
    }
}
