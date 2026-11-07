<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Drivers;

use App\Access\AccessLeaf;
use App\Auth\Providers\AttemptResult;
use App\Auth\Providers\AuthComponent;
use App\Auth\Providers\BindingContext;
use App\Auth\Providers\ProbeResult;
use App\Auth\Providers\ReaderPresentation;

/**
 * §8.12.17's `portal_session`: the reader established a session through
 * §8.12.10's handoff.
 *
 * 🛑 **This is Phase 22's mechanism acquiring a name.** P22 shipped the handoff,
 * the per-origin session and the grant, and hard-coded the resulting leaf as
 * `{binding}` in `ReaderSessions`. §8.12.17 calls that driver
 * `portal_session`, and this class is where the hard-coding stops: a policy
 * rule can now say `{"leaf": "binding", "driver": "portal_session"}` and mean
 * "anybody who signed in to the dashboard", distinct from "anybody our IdP
 * vouched for".
 *
 * 🛑 It verifies **nothing**, and that is correct rather than lazy. The session
 * was verified by `ReaderSessions::resolve()` — hashed handle, per-origin
 * scoping, three expiry conditions — before this driver is reached. A driver
 * that re-verified it would be a second implementation of "is this session
 * live", which is exactly what that class's sole-call-site architecture test
 * forbids.
 *
 * What it adds is the **binding** dimension: §12.3 lets a rule name a specific
 * binding, so a project with both a portal and an IdP can write one rule per
 * audience, and a dashboard member does not satisfy the IdP's rule.
 */
final class PortalSessionDriver implements AuthComponent
{
    public static function type(): string
    {
        return 'portal_session';
    }

    public static function leaf(): AccessLeaf
    {
        return AccessLeaf::Binding;
    }

    public static function allowsProjectScope(): bool
    {
        return true;
    }

    public static function mayMapDashboardRoles(): bool
    {
        /*
         * 🛑 False, even though this driver's readers **are** dashboard users.
         *
         * §8.12.5 is about a binding *producing* a role — mapping a provider
         * group onto one of §12.1's fixed roles. A portal-session reader
         * already holds whatever roles they hold; the binding grants nothing.
         * Returning true here would let a project-scoped binding award roles,
         * which the requirement forbids "enforced both as a driver capability
         * flag and as a validation invariant".
         */
        return false;
    }

    /** @param  array<string, mixed>  $config */
    public function validate(array $config): array
    {
        /* Nothing to configure: the session machinery is the installation's. */
        return [];
    }

    public function probe(BindingContext $binding): ProbeResult
    {
        /*
         * 🛑 The one thing worth checking, and §8.1.4 is why: the handoff needs
         * two registrable domains. Under `DOCUP_UNSAFE_SINGLE_ORIGIN` §8.1.5
         * forces every project public and disables private sharing, so a
         * portal-session binding on such an installation is configuration that
         * cannot do anything — and a probe that passed would say otherwise.
         */
        if (config('docup.unsafe.single_origin') === true) {
            return ProbeResult::fail(
                'DOCUP_UNSAFE_SINGLE_ORIGIN forces every project public (§8.1.5), '
                .'so a reader session cannot guard anything',
            );
        }

        $dashboard = config('docup.origins.app');
        $docs = config('docup.origins.docs');

        if (! is_string($dashboard) || $dashboard === '' || ! is_string($docs) || $docs === '') {
            return ProbeResult::fail('the dashboard and documentation origins are not both configured');
        }

        return ProbeResult::pass('the handoff can reach the dashboard at '.$dashboard);
    }

    public function attempt(BindingContext $binding, ReaderPresentation $presented): AttemptResult
    {
        $subject = $presented->sessionSubject;

        if ($subject === null) {
            /*
             * 🛑 `unsatisfied`, not `rejected`. No session cookie is the
             * ordinary state of a first visit; `ReaderResolver` is what knows
             * the difference between "no cookie" and "a cookie that resolved to
             * nothing", and it reports the second itself.
             */
            return AttemptResult::unsatisfied();
        }

        /*
         * 🛑 No scope. §12.3's last conjunct applies a scope only for `{share}`
         * and `{bearer}`, and a portal session is neither: a reader who signed
         * in is admitted by whatever the rule says, not narrowed to a path a
         * credential named.
         */
        return AttemptResult::satisfiedBy(AccessLeaf::Binding, subject: $subject);
    }
}
