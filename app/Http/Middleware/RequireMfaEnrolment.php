<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Auth\MfaEnforcement;
use App\Models\User;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * 🛑 §8.13.4's enforcement, at the one place a dashboard request passes.
 *
 * {@see MfaEnforcement} decides *whether* this person must enrol; this decides
 * what happens to the request they just made. The split matters because the
 * second question has an answer that is easy to get wrong in a way nobody
 * notices until somebody is locked out of their own installation with no way
 * back in.
 *
 * ## 🛑 What must stay reachable, and why each one
 *
 * A gate that blocks everything blocks the remedy. So:
 *
 * - **The enrolment page and Fortify's two-factor endpoints.** Obviously — but
 *   it is worth being explicit that this includes the `POST`/`DELETE` routes,
 *   not only the page: enrolling is a mutation, and a gate that allowed the
 *   form and blocked its submission would read as a broken page.
 * - **Password confirmation.** `config/fortify.php` sets
 *   `'confirmPassword' => true` on two-factor, so enrolment *redirects through*
 *   the confirm-password screen. Blocking it would make enrolment a loop:
 *   enrol → confirm → blocked → enrol.
 * - **Logout.** A person who cannot enrol on this device has to be able to get
 *   out. Holding them in a session they cannot use is not a security control.
 * - **The health endpoints**, which carry no session and are not reached
 *   through this group anyway, named here so a later change to the group does
 *   not quietly take out liveness probes.
 *
 * ## 🛑 Why a redirect rather than a 403
 *
 * The person is **authorised**; they have not finished setting up. A 403 says
 * "you may not", which sends them to an administrator who can do nothing for
 * them. The redirect carries them to the one page that fixes it. An API
 * request gets the 403, because there is nobody there to redirect.
 *
 * ## 🛑 Why this is not on the API-token routes
 *
 * §8.13.6 makes an API token a separate principal with its own capability
 * ceiling, and MFA is a property of a human authentication event. A token that
 * had to pass an MFA check would have to carry a second factor, which is the
 * definition of a credential that is not a second factor. The dashboard session
 * is where the human is.
 */
final class RequireMfaEnrolment
{
    /**
     * Route name prefixes that must stay reachable so the remedy is reachable.
     *
     * 🛑 Matched on the **route name**, never on the path. A path prefix would
     * be a second source of truth for where Fortify's endpoints live, and
     * `config/fortify.php` can move them — at which point a path-matched
     * allowlist stops allowing anything and nobody can enrol.
     *
     * @var list<string>
     */
    private const array PERMITTED = [
        'two-factor.',
        'mfa.',
        'password.confirm',
        'password.confirmation',
        'logout',
    ];

    public function handle(Request $request, \Closure $next): Response
    {
        $user = $request->user();

        if (! $user instanceof User) {
            return $next($request);
        }

        if (self::isPermitted($request)) {
            return $next($request);
        }

        if (! app(MfaEnforcement::class)->blocks($user)) {
            return $next($request);
        }

        /*
         * 🛑 A 403 for a client with nobody behind it. `expectsJson()` covers
         * the dashboard's own XHR as well as a script, and that is correct:
         * Inertia follows a redirect, so a plain redirect to an Inertia request
         * would render the enrolment page inside whatever component asked.
         */
        if ($request->expectsJson() && ! $request->header('X-Inertia')) {
            return response()->json([
                'message' => 'Two-factor authentication is required for your role before you can continue.',
                'code' => 'mfa_enrolment_required',
            ], 403);
        }

        return redirect()->route('mfa.enrol');
    }

    /**
     * Whether this request is one of the few that must get through.
     *
     * 🛑 Prefix matching on the route name, so `two-factor.` covers Fortify's
     * whole family — enable, confirm, disable, recovery codes, QR code — in one
     * entry. Listing them individually is how the next Fortify version adds one
     * and nobody can finish enrolling.
     */
    private static function isPermitted(Request $request): bool
    {
        $name = $request->route()?->getName();

        if (! is_string($name)) {
            /*
             * 🛑 An unnamed route is **not** permitted. Failing closed: a route
             * somebody forgot to name should not become an exemption from the
             * installation's authentication policy by omission.
             */
            return false;
        }

        foreach (self::PERMITTED as $prefix) {
            if (str_starts_with($name, $prefix)) {
                return true;
            }
        }

        return false;
    }
}
