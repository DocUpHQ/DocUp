<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers;

use Symfony\Component\HttpFoundation\Response;

/**
 * The two responses the handoff endpoints may produce when they refuse.
 *
 * 🛑 One is a bare 404 and the other is a visible error page, and the division
 * is §8.12.23's:
 *
 * - {@see self::notFound()} for **everything an attacker could be probing**:
 *   an unknown host, an unknown code, a replayed code, a wrong audience, a
 *   failed verifier. §8.12.23 makes 404 the default "for unauthorised or
 *   unresolvable resources" and forbids the response varying; the reason goes
 *   to §8.22's audit chain and nowhere else.
 * - {@see self::cookiesBlocked()} for the one failure that is **the reader's
 *   own browser** and that no amount of retrying will fix. A 404 there would
 *   be technically consistent and practically cruel: the reader can see the
 *   project exists, they have just been told to sign in, and they are now
 *   looking at a page that says the site is not there.
 *
 * The second leaks nothing, because reaching it requires having completed a
 * handoff — which requires having been signed in and permitted.
 */
final readonly class ReaderRejection
{
    /** §8.12.23's default, with nothing in the body. */
    public static function notFound(): Response
    {
        return new Response('', 404, self::headers());
    }

    /**
     * 🛑 §18.10's failure mode, made visible instead of infinite.
     *
     * The assumption §18 records — that a `__Host-`, `SameSite=Lax` cookie is
     * accepted on the 302 back from the dashboard — is unverified in Safari and
     * Firefox under the strictest third-party cookie blocking. Phase 22 does
     * not rest on it: the callback sets the cookie from a same-origin document
     * rather than a redirect (§18.10's own "if wrong" mitigation), and if the
     * cookie *still* does not stick, the reader arrives here after one retry
     * rather than bouncing forever.
     *
     * 409 rather than 403 or 500: nothing is forbidden and nothing failed on
     * the server. The request conflicts with the state of the reader's own
     * browser, which is what 409 means and what the body says.
     */
    public static function cookiesBlocked(): Response
    {
        $body = <<<'HTML'
        <!DOCTYPE html>
        <html lang="en"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Sign-in could not complete</title>
        <style>
          body{font:16px/1.6 system-ui,sans-serif;margin:0;padding:3rem 1.5rem;max-width:34rem}
          h1{font-size:1.4rem;margin:0 0 1rem}
          code{background:#f4f4f5;padding:.1em .3em;border-radius:3px}
        </style></head><body>
        <h1>Sign-in could not complete</h1>
        <p>Your browser did not keep the session cookie this site needs, so the
        sign-in returned you here without signing you in.</p>
        <p>This is usually one of:</p>
        <ul>
          <li>cookies blocked for this site,</li>
          <li>strict tracking protection treating the sign-in redirect as
              cross-site, or</li>
          <li>private browsing with site data disabled.</li>
        </ul>
        <p>Allowing cookies for this site and trying again will fix it.</p>
        </body></html>
        HTML;

        return new Response($body, 409, self::headers() + ['Content-Type' => 'text/html; charset=utf-8']);
    }

    /**
     * 🛑 Never cacheable, and never indexed.
     *
     * §9.3.2 keeps private content out of a shared cache; a handoff response
     * is not content at all, and a cached one would serve a stale stage of
     * somebody else's sign-in.
     *
     * @return array<string, string>
     */
    private static function headers(): array
    {
        return [
            'Cache-Control' => 'private, no-store',
            'Vary' => 'Cookie',
            'X-Robots-Tag' => 'noindex, nofollow',
        ];
    }
}
