<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Auth\Capability;
use App\Auth\SessionStamps;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

/**
 * Step-up re-authentication (§8.13.5).
 *
 * §8.13.5: within **5 minutes** for mutations to authentication providers,
 * domains, visibility, share grants, token minting and audit export; **15
 * minutes** otherwise.
 *
 * 🛑 Why two windows rather than one. A single long window makes the control
 * theatre — a session stolen an hour in still holds it. A single short window
 * makes every ordinary edit re-prompt, and a product that asks for a password
 * ten times an hour trains people to type it without reading the page, which
 * is how phishing works. The split puts the friction where the damage is.
 *
 * Used as `stepup:5` or `stepup:<capability>`, so a route declares which
 * sensitivity applies rather than this class holding a list of route names that
 * drifts from the routes.
 */
final class RequireRecentAuthentication
{
    public const SENSITIVE_MINUTES = 5;

    public const ROUTINE_MINUTES = 15;

    /**
     * 🛑 The §8.13.5 list, as capabilities rather than route names.
     *
     * Expressed this way so the window follows the *power being exercised*. A
     * list of route names has to be updated whenever a route is added, and the
     * failure of forgetting is silent: the new route gets the lenient window
     * and nobody notices.
     *
     * @var list<string>
     */
    private const SENSITIVE = [
        'installation.idp.manage',      // authentication providers
        'installation.audit.export',    // audit export
        'project.visibility.update',    // visibility
        'token.mint',                   // token minting
        // Domains and share grants arrive in Phases 10 and 21; their
        // capabilities join this list when they exist, which is why the list
        // names capabilities that can be checked rather than routes that cannot.
    ];

    public function handle(Request $request, \Closure $next, ?string $for = null): Response
    {
        if (! Auth::check()) {
            return $next($request);
        }

        $window = $this->windowFor($for);
        $confirmedAt = $request->session()->get(SessionStamps::CONFIRMED_AT);

        // Fail closed: no stamp means not confirmed, never "assume the login
        // counted". The login flow stamps it explicitly.
        $fresh = is_int($confirmedAt) && now()->getTimestamp() - $confirmedAt < $window * 60;

        if (! $fresh) {
            if ($request->expectsJson()) {
                /*
                 * 403 with a machine-readable reason, not 401: the credentials
                 * are valid and the session is live, so 401 would send an API
                 * client into a re-login loop it cannot complete. What is
                 * missing is a recent interactive confirmation, which only a
                 * human at a browser can give — and saying so is the difference
                 * between a client that surfaces the problem and one that
                 * retries for ever.
                 */
                return response()->json([
                    'message' => 'Re-authentication required.',
                    'reason' => 'step_up_required',
                    'window_minutes' => $window,
                ], 403);
            }

            return redirect()->route('password.confirm')
                ->with('intended', $request->fullUrl());
        }

        return $next($request);
    }

    /**
     * Minutes allowed for the given sensitivity.
     *
     * Accepts an explicit integer, a capability string, or nothing. An
     * unrecognised value gets the **short** window: a typo in a route
     * declaration must not silently widen the control.
     */
    private function windowFor(?string $for): int
    {
        if ($for === null) {
            return self::ROUTINE_MINUTES;
        }

        if (ctype_digit($for)) {
            return max(1, min((int) $for, self::ROUTINE_MINUTES));
        }

        if (in_array($for, self::SENSITIVE, true)) {
            return self::SENSITIVE_MINUTES;
        }

        // A known capability that is not on the sensitive list is routine.
        if (Capability::tryFrom($for) instanceof Capability) {
            return self::ROUTINE_MINUTES;
        }

        return self::SENSITIVE_MINUTES;
    }

    /** Whether a capability is on the §8.13.5 sensitive list. */
    public static function isSensitive(Capability $capability): bool
    {
        return in_array($capability->value, self::SENSITIVE, true);
    }
}
