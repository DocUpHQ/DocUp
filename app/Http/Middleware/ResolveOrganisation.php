<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Auth\OrganisationContext;
use App\Auth\RoleResolver;
use App\Models\Organisation;
use App\Models\User;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Binds the request to one organisation and declares the tenancy context
 * (§8.2.1, §8.2.2).
 *
 * 🛑 **404, never 403** (§8.2.2), through the UI, the API and direct identifier
 * access alike. Every rejection here is `abort(404)`, and the reason is worth
 * stating because 403 is the instinctive choice: a 403 confirms the
 * organisation exists. An attacker enumerating slugs learns which tenants are
 * real, which is itself the leak — "forbidden" and "no such thing" must be
 * indistinguishable from outside.
 *
 * The context is declared *after* membership is confirmed, so a request that
 * fails the check never reaches a query that could return another tenant's
 * rows. {@see OrganisationContext} throws when undeclared, so the ordering is
 * enforced rather than merely intended.
 */
final class ResolveOrganisation
{
    public function __construct(
        private readonly OrganisationContext $context,
        private readonly RoleResolver $roles,
    ) {}

    public function handle(Request $request, \Closure $next): Response
    {
        $parameter = $request->route('organisation');
        $slug = is_string($parameter) ? $parameter : null;

        if ($slug === null) {
            abort(404);
        }

        $user = $request->user();

        // An unauthenticated request has no tenant. Also 404 rather than 401:
        // this middleware runs behind `auth`, so reaching it unauthenticated is
        // a misconfiguration, and failing closed is the safe reading.
        if (! $user instanceof User) {
            abort(404);
        }

        /*
         * Resolved outside the tenancy scope on purpose: `organisations` is the
         * tenancy root and carries no `organisation_id`, so there is nothing to
         * filter on, and the context has not been declared yet.
         */
        $organisation = Organisation::query()->where('slug', $slug)->first();

        if (! $organisation instanceof Organisation) {
            abort(404);
        }

        /*
         * 🛑 Membership is what makes the 404 real.
         *
         * Without this check the tenancy scope would still hide the
         * organisation's *projects*, but the organisation itself would resolve
         * — so a stranger could confirm a tenant exists by its slug, and any
         * endpoint that reported organisation-level data before touching a
         * scoped table would leak it.
         *
         * "Membership" is holding any role that bears on this organisation,
         * which includes installation-scope roles: §12.1's chain means an
         * installation owner is a member of every organisation without needing
         * a row per tenant.
         */
        if ($this->roles->rolesFor($user, null, $organisation->id) === []) {
            abort(404);
        }

        $this->context->for($organisation->id);

        $request->attributes->set('organisation', $organisation);

        return $next($request);
    }
}
