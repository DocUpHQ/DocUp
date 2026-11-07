<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Readers;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Models\Project;
use App\Models\User;
use App\Readers\Grants\Grant;
use App\Readers\HandoffRefused;
use App\Readers\ReaderCookies;
use App\Readers\ReaderHandoff;
use App\Readers\ReaderHandoffState;
use App\Readers\ReaderRejection;
use App\Readers\ReaderSessions;
use App\Serving\RoutingSnapshotLoader;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * §20.2's `/_/auth/callback`: §8.12.10's step 3, on the documentation origin.
 *
 * 🛑 **This is where §18.10 stops being a dependency**, and the reasoning is
 * worth having beside the code because the assumption is still unverified.
 *
 * §18 records: "A `__Host-`, `SameSite=Lax`, HttpOnly grant cookie is sent on
 * the top-level 302 back from the dashboard to the documentation origin, in
 * Chrome, Firefox and Safari under the strictest third-party cookie blocking."
 * Its *if wrong* column already names the remedy: "The callback serves a tiny
 * same-origin interstitial that sets the cookie and navigates with
 * `location.replace()`. One extra paint per domain, no model change."
 *
 * Phase 22 ships the remedy **unconditionally**, so the assumption's outcome
 * changes nothing:
 *
 * 1. It cannot be verified here. Safari and Firefox under their strictest
 *    settings are not available to this build, and shipping the un-mitigated
 *    form would mean shipping a feature whose failure mode is an infinite
 *    redirect loop in a browser nobody tested.
 * 2. The interstitial is strictly better regardless. A 302 that silently loses
 *    its cookie produces a loop with no error anywhere; a document that sets
 *    the cookie and then navigates gives the next request somewhere to notice
 *    ({@see ReaderHandoff::MAX_ATTEMPTS}) and the reader a page that explains
 *    itself ({@see ReaderRejection::cookiesBlocked()}).
 * 3. The cost is one paint per origin per session — once every eight to
 *    twenty-four hours — against a redirect that was going to happen anyway.
 *
 * 🛑 So §18.10 should be recorded as **not depended upon** rather than left
 * open: the mitigation is the default, and verifying the assumption later would
 * only ever let somebody remove a safety net. That is a proposed amendment
 * (§1.1), not a silent divergence.
 */
final readonly class AuthCallbackController
{
    public function __construct(
        private RoutingSnapshotLoader $snapshots,
        private ReaderHandoff $handoff,
        private ReaderSessions $sessions,
    ) {}

    public function __invoke(Request $request): Response
    {
        $snapshot = $this->snapshots->load((string) $request->getHost());

        if (! $snapshot->servable || $snapshot->domainId === null) {
            return ReaderRejection::notFound();
        }

        $code = $request->query('code');
        $state = ReaderHandoffState::fromCookie($request->cookies->get(ReaderCookies::STATE));

        if (! is_string($code) || $code === '' || $state === null) {
            /*
             * 🛑 A missing state cookie is indistinguishable from a reader
             * whose browser dropped it, so it gets the same visible page the
             * loop breaker gives rather than a 404. There is nothing to probe
             * here: reaching this point with no cookie reveals only that the
             * endpoint exists, which §20.2 publishes.
             */
            return ReaderRejection::cookiesBlocked();
        }

        /*
         * The project, from the mount covering where the reader was going —
         * the same question {@see AuthStartController} asked, answered the same
         * way so the two halves cannot disagree about which project the code
         * was minted for.
         */
        $match = $snapshot->matchFor($state->returnPath);

        if ($match === null) {
            return ReaderRejection::notFound();
        }

        $projectId = $match->mount->project->id;

        try {
            $redeemed = $this->handoff->redeem(
                code: $code,
                projectId: $projectId,
                domainId: $snapshot->domainId,
                verifier: $state->verifier,
            );
        } catch (HandoffRefused $refused) {
            /*
             * 🛑 §8.22's chain gets the reason; the reader gets §8.12.23's
             * default and nothing else. The organisation is known because the
             * snapshot resolved, so the event has a chain to append to.
             */
            Audit::record(
                action: 'reader.handoff.refused',
                actorType: ActorType::System,
                organisationId: $match->mount->project->organisationId,
                subjectType: 'project',
                subjectId: $projectId,
                payload: ['reason' => $refused->rejection->value],
            );

            return ReaderRejection::notFound();
        }

        $user = User::query()->find($redeemed['userId']);
        $project = Project::query()->withoutGlobalScopes()->find($projectId);

        if (! $user instanceof User || ! $project instanceof Project) {
            return ReaderRejection::notFound();
        }

        $established = $this->sessions->establish(
            project: $project,
            domainId: $snapshot->domainId,
            subject: $user,
            combinedEpoch: Grant::combinedEpoch(
                $match->mount->project->authzEpoch,
                $match->mount->project->identityEpoch,
            ),
        );

        /*
         * 🛑 **The interstitial, not a redirect.** See the class note: the
         * cookies are set on a document this origin serves, and the navigation
         * happens from inside it.
         *
         * `location.replace()` rather than `assign()` so the callback URL — the
         * one carrying a spent code — does not enter the history. A reader
         * pressing Back would otherwise re-request it, get a refusal for an
         * already-used code, and see a 404 where they expected the page they
         * came from.
         *
         * 🛑 And the `<meta refresh>` beside it is the no-JavaScript path.
         * Documentation readers with scripting disabled are a real population,
         * and a sign-in that needs JavaScript to complete would exclude them
         * from private documentation entirely.
         */
        $response = new Response(
            self::interstitial($state->returnPath),
            200,
            [
                'Content-Type' => 'text/html; charset=utf-8',
                'Cache-Control' => 'private, no-store',
                'Vary' => 'Cookie',
                'X-Robots-Tag' => 'noindex, nofollow',
                /*
                 * 🛑 **This header matters more here than anywhere else in the
                 * product.** This document's own URL carries the handoff code
                 * in its query string, and the next thing that happens is a
                 * navigation away from it — which would otherwise send this URL
                 * as the `Referer`, into the access log of whatever the
                 * documentation page loads. The code is spent by then, but
                 * §8.12.10's thirty-second window and a clock skew are not a
                 * margin worth relying on, and a spent code in a third party's
                 * log is still a record of who read what.
                 */
                'Referrer-Policy' => 'no-referrer',
                /*
                 * 🛑 This one page is the only HTML the application itself
                 * serves on a documentation origin, so it carries its own
                 * CSP — and a strict one, which §8.14.15's "permissive by
                 * default" rule does not cover because that rule is about
                 * *documentation*. Nothing here loads anything.
                 */
                'Content-Security-Policy' => "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'",
            ],
        );

        $response->headers->setCookie(ReaderCookies::session($established['handle']));
        $response->headers->setCookie(ReaderCookies::cacheKey($established['cacheKey']));

        /*
         * 🛑 The state cookie is cleared here, which is what makes the attempt
         * counter mean something: a handoff that got this far succeeded, so the
         * next one starts from zero. Leaving it would make the second genuine
         * sign-in of the day look like a retry.
         */
        $response->headers->setCookie(ReaderCookies::forget(ReaderCookies::STATE));

        return $response;
    }

    /**
     * The interstitial document.
     *
     * 🛑 The destination is a **path** that {@see ReaderHandoff::safeReturnPath()}
     * has already normalised, and it is escaped again on the way into both the
     * HTML attribute and the JavaScript string. Two encodings for two contexts:
     * `htmlspecialchars` for the `<meta>` and `json_encode` for the script, so
     * neither a quote nor a `</script>` in a path can break out.
     */
    private static function interstitial(string $returnPath): string
    {
        $html = htmlspecialchars($returnPath, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $js = (string) json_encode($returnPath, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);

        return <<<HTML
        <!DOCTYPE html>
        <html lang="en"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta http-equiv="refresh" content="0; url={$html}">
        <title>Signing in…</title>
        <style>body{font:16px/1.6 system-ui,sans-serif;margin:0;padding:3rem 1.5rem}</style>
        </head><body>
        <p>Signing in… <a href="{$html}">continue</a>.</p>
        <script>location.replace({$js});</script>
        </body></html>
        HTML;
    }
}
