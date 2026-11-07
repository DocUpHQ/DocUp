<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Readers;

use App\Readers\ReaderCookies;
use App\Readers\ReaderHandoff;
use App\Readers\ReaderRejection;
use App\Readers\ReaderSessions;
use App\Serving\RoutingSnapshotLoader;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Ending a reader session on **this** origin.
 *
 * 🛑 §17's exit criterion, and the whole point of §8.12.10's per-origin design:
 * "Logging out of project A leaves project B signed in." There is no global
 * reader logout and there cannot be one, because there is no cookie that spans
 * the origins — which is the same fact that made the handoff necessary in the
 * first place.
 *
 * 🛑 **POST only.** A `GET` logout is triggerable by any `<img>` on any site,
 * which turns signing readers out into a one-line attack. The documentation
 * origin has no CSRF token — `routes/docs.php` admits no `web` group — so the
 * method is the whole of the protection, and it is enough: the worst a forged
 * POST achieves is a reader who has to sign in again, and the session is
 * revoked server-side either way.
 *
 * 🛑 And `Clear-Site-Data` is **not** sent, under any circumstances. §8.14.17:
 * "`Clear-Site-Data: "cookies"` MUST NEVER be sent on a documentation host —
 * its scope spans the whole registrable domain and would log out every tenant
 * on it." Four `Set-Cookie` expiries do the job with no blast radius.
 */
final readonly class LogoutController
{
    public function __construct(
        private RoutingSnapshotLoader $snapshots,
        private ReaderSessions $sessions,
    ) {}

    public function __invoke(Request $request): Response
    {
        $snapshot = $this->snapshots->load((string) $request->getHost());

        if (! $snapshot->servable || $snapshot->domainId === null) {
            return ReaderRejection::notFound();
        }

        $returnPath = ReaderHandoff::safeReturnPath((string) $request->input('return', '/'));
        $handle = $request->cookies->get(ReaderCookies::SESSION);

        if (is_string($handle) && $handle !== '') {
            $match = $snapshot->matchFor($returnPath);

            /*
             * 🛑 Resolved against the mount, so a handle can only end a session
             * on the project and domain it belongs to. Without the project in
             * the lookup, a reader holding a session on project A could post a
             * logout naming project B's path and the handle would simply not
             * match — which is the behaviour wanted, but by accident rather
             * than by construction.
             */
            if ($match !== null) {
                $session = $this->sessions->resolve(
                    $handle,
                    $match->mount->project->id,
                    $snapshot->domainId,
                );

                if ($session !== null) {
                    /*
                     * 🛑 Bumps `identity_epoch` for this project only, which is
                     * what makes the outstanding grant in the reader's own
                     * cookie stop verifying on the next request — §8.12.15's
                     * "takes effect on the next request", with no purge.
                     */
                    $this->sessions->revoke($session, 'reader_logout');
                }
            }
        }

        $response = new RedirectResponse($returnPath, 302, [
            'Cache-Control' => 'private, no-store',
            'Vary' => 'Cookie',
            'X-Robots-Tag' => 'noindex, nofollow',
        ]);

        /*
         * 🛑 All four of §12.4's documentation-origin cookies, including the
         * state cookie. A logout that left a stale verifier behind would make
         * the next sign-in start at attempt two, and the loop breaker would
         * refuse the reader's first honest try.
         */
        foreach ([ReaderCookies::SESSION, ReaderCookies::GRANT, ReaderCookies::CACHE_KEY, ReaderCookies::STATE] as $name) {
            $response->headers->setCookie(ReaderCookies::forget($name));
        }

        return $response;
    }
}
