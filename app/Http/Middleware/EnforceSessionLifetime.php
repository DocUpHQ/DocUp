<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Auth\SessionStamps;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

/**
 * The §8.13.3 session lifetimes: 15-minute idle, 12-hour absolute.
 *
 * 🛑 **Two separate limits, and Laravel only has one.**
 *
 * `config('session.lifetime')` is an idle timeout: every request renews it. On
 * its own, a session lives for ever as long as somebody keeps clicking — which
 * is precisely the session a stolen laptop or a hijacked cookie gives an
 * attacker. §8.13.3 therefore also fixes an absolute ceiling measured from
 * authentication, which nothing renews.
 *
 * The idle limit is enforced here rather than by shortening
 * `session.lifetime`, because that value also governs how long the session
 * *record* survives, and a 15-minute store lifetime would discard the
 * `authenticated_at` stamp that the absolute limit is measured from.
 */
final class EnforceSessionLifetime
{
    /** §8.13.3. Minutes of inactivity before the session is abandoned. */
    public const IDLE_MINUTES = 15;

    /** §8.13.3. Hours from authentication, renewed by nothing. */
    public const ABSOLUTE_HOURS = 12;

    public function handle(Request $request, \Closure $next): Response
    {
        if (! Auth::check()) {
            return $next($request);
        }

        $session = $request->session();
        $now = now();

        $authenticatedAt = $session->get(SessionStamps::AUTHENTICATED_AT);
        $lastActivityAt = $session->get(SessionStamps::LAST_ACTIVITY_AT);

        /*
         * 🛑 Fail closed on a missing stamp.
         *
         * An authenticated session with no `authenticated_at` is one this
         * middleware cannot age — so it is ended rather than exempted. The
         * alternative is a session that is immortal precisely because something
         * forgot to stamp it, which is the worst possible direction for the bug
         * to lean.
         */
        $expired = ! is_int($authenticatedAt)
            || $now->getTimestamp() - $authenticatedAt >= self::ABSOLUTE_HOURS * 3600
            || (is_int($lastActivityAt) && $now->getTimestamp() - $lastActivityAt >= self::IDLE_MINUTES * 60);

        if ($expired) {
            Auth::logout();

            $session->invalidate();

            // A fresh token, or the login form the user lands on fails CSRF and
            // presents as "your password is wrong".
            $session->regenerateToken();

            return $request->expectsJson()
                ? response()->json(['message' => 'Session expired.'], 401)
                : redirect()->guest(route('login'));
        }

        $session->put(SessionStamps::LAST_ACTIVITY_AT, $now->getTimestamp());

        return $next($request);
    }
}
