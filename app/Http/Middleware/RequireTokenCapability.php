<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Auth\Capability;
use App\Auth\RoleResolver;
use App\Models\ApiToken;
use App\Models\Project;
use App\Models\User;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Requires a capability of both the token and the person who minted it
 * (§8.13.6, §12.1).
 *
 * 🛑 **Both**, and the second half is the one that matters. A token's capability
 * list is a snapshot taken at mint; the holder's roles are live. Checking only
 * the token would mean a token minted by a project admin keeps publishing after
 * that person is removed from the project — the credential outliving the
 * authority it was derived from, which is how a departed contributor keeps
 * write access to a documentation site.
 *
 * §8.13.3 defines a permission epoch for exactly this problem and comparing it
 * per request is still owed (recorded in the Phase 02 build-log entry). Until
 * then, re-resolving the holder's roles on each request is the live check, and
 * it is cheap because {@see RoleResolver} is memoised per request.
 */
final class RequireTokenCapability
{
    public function __construct(private readonly RoleResolver $roles) {}

    /**
     * @param  string  $capability  a {@see Capability} value, from the route definition
     */
    public function handle(Request $request, \Closure $next, string $capability): Response
    {
        $required = Capability::tryFrom($capability);

        if ($required === null) {
            /*
             * A route naming a capability that does not exist is a programming
             * error, and it must not be allowed to read as "permitted". Thrown
             * rather than treated as a denial so it surfaces in CI as the typo
             * it is, instead of as a mysterious 403 in production.
             */
            throw new \ValueError("Route requires unknown capability [{$capability}].");
        }

        $token = $request->attributes->get(AuthenticateApiToken::ATTRIBUTE);

        if (! $token instanceof ApiToken) {
            return $this->forbidden();
        }

        if (! $token->grants($required)) {
            return $this->forbidden();
        }

        $holder = $token->user;

        if (! $holder instanceof User) {
            return $this->forbidden();
        }

        $project = $this->project($request);

        /*
         * 🛑 §8.2.2: **404, never 403.** A route naming a project that does not
         * resolve inside the caller's tenant answers "no such thing" here,
         * before any capability is weighed — otherwise this middleware reports
         * 403 for another organisation's project, and 403 is the answer that
         * confirms the row exists.
         *
         * It was 403 until Phase 03's cross-tenant test caught it, and the
         * reason the slip was easy is that the leak is indirect: a missing
         * project resolves to null, null resolves to the organisation-only
         * capability set, and a project-scoped role is absent from that set — so
         * the denial arrived for a plausible-looking reason that happened to be
         * the wrong one.
         */
        if ($this->addressesAProject($request) && ! $project instanceof Project) {
            return $this->notFound();
        }

        /*
         * 🛑 Resolved WITH the project, not just the organisation. §12.1's
         * chain is additive over installation → organisation → collection →
         * project, so a `project_writer`'s role row is scoped to the project
         * and an organisation-only resolution cannot see it. Passing null here
         * would have denied every project-scoped role — publishing would have
         * worked only for organisation administrators, which is precisely
         * backwards.
         */
        $held = $this->roles->capabilitiesFor($holder, $project, $token->organisation_id);

        if (! in_array($required, $held, true)) {
            return $this->forbidden();
        }

        return $next($request);
    }

    /** Whether this route names a project at all. */
    private function addressesAProject(Request $request): bool
    {
        return $request->route('project') !== null;
    }

    /**
     * The project this request addresses, if any.
     *
     * 🛑 Does not assume route-model binding has run. Middleware ordering
     * against `SubstituteBindings` has already caught this project out once —
     * see the note in `bootstrap/app.php` about `ResolveOrganisation` — and a
     * capability check that silently sees `null` because it ran too early is
     * the same failure in a worse place. So a bound model is used when present
     * and otherwise the raw value is resolved through the model's **own**
     * binding rule, which keeps one implementation of "slug or UUID" rather
     * than a second copy here.
     */
    private function project(Request $request): ?Project
    {
        $parameter = $request->route('project');

        if ($parameter instanceof Project) {
            return $parameter;
        }

        if (! is_string($parameter) || $parameter === '') {
            return null;
        }

        $resolved = (new Project)->resolveRouteBinding($parameter);

        return $resolved instanceof Project ? $resolved : null;
    }

    /**
     * 403, not 404.
     *
     * §8.2.2's "404, never 403" is about **tenant** boundaries: whether another
     * organisation's project exists must not be discoverable. This is a
     * different question. The caller has already proved they belong to this
     * tenant and the resource they named has already resolved inside it — so
     * there is nothing left to conceal, and answering 404 here would tell an
     * author that their own project does not exist.
     */
    /**
     * 404 for a project that is not reachable from this token's tenant.
     *
     * The same body the publish controller returns, so the two cannot be told
     * apart. §8.2.2 wants "forbidden" and "no such thing" indistinguishable
     * from outside, and a distinguishable 404 would be the same leak wearing a
     * different status code.
     */
    private function notFound(): Response
    {
        return response()->json(['error' => 'not_found'], 404);
    }

    private function forbidden(): Response
    {
        return response()->json([
            'error' => 'forbidden',
            'message' => 'This token does not carry the capability required for that action.',
        ], 403);
    }
}
