<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Http\Controllers\Api\ProjectController as ApiProjectController;
use App\Http\Controllers\Api\ProjectVersionController as ApiProjectVersionController;
use App\Http\Controllers\BreakGlassController;
use App\Http\Controllers\Health\LiveController;
use App\Http\Controllers\Health\ReadyController;
use App\Http\Controllers\Health\SelfTestController;
use App\Http\Controllers\MfaEnrolmentController;
use App\Http\Controllers\PolicySimulatorController;
use App\Http\Controllers\ProjectController;
use App\Http\Controllers\ProjectVisibilityController;
use App\Http\Controllers\Readers\HandoffController;
use App\Http\Controllers\Readers\LdapSignInController;
use App\Http\Controllers\Readers\OidcCallbackController;
use App\Http\Controllers\Readers\OidcStartController;
use App\Http\Controllers\Readers\SamlAcsController;
use App\Http\Controllers\Readers\SamlStartController;
use App\Http\Controllers\SchemaController;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Support\Facades\Route;
use Inertia\Inertia;

/*
| Phase 01 served one page: the login form. Phase 02 adds the organisation and
| project surfaces behind authentication.
*/

/*
| §8.1.10's health endpoints. Registered FIRST and outside every middleware
| group: an orchestrator's liveness probe must not depend on sessions, on
| tenancy resolution or on anything else that could itself be the thing that
| is broken.
|
| 🛑 These replace `withRouting(health: '/up')`, which is silently IGNORED
| when `using:` is supplied - as it is in bootstrap/app.php, for the route
| ordering reason recorded there. `/up` 404'd and the compose healthcheck
| had been failing against it since Phase 01.
*/
Route::prefix('_/health')->name('health.')->group(function (): void {
    Route::get('/', LiveController::class)->name('live');
    Route::get('ready', ReadyController::class)->name('ready');
    Route::get('self-test', SelfTestController::class)->name('self-test');
});

/*
| §8.1.11's `.docup.yaml` schema, published. Outside every middleware group
| for the same reason the health endpoints are: an author's editor fetches
| this to offer completion while they write the file, and a contract that
| needed a session would not be one.
|
| 🛑 The version is in the PATH, not in a header or a query parameter. §8.1.11
| gives each contract "a two-minor deprecation policy", which only means
| anything if v1 keeps saying what it said — so a v2 is a second URL rather
| than a change to this one.
*/
Route::get('_/schema/docup-yaml/v1.json', [SchemaController::class, 'show'])->name('schema.docup-yaml.v1');

/*
| §8.19.3's incoming provider webhooks are NOT here. This file is wrapped in
| the `web` middleware group (see bootstrap/app.php), which validates a CSRF
| token — and a provider has no session and cannot obtain one, so the route
| lives in routes/api.php where it declares its own middleware. Said out
| loud because "put it next to the other unauthenticated endpoints" is the
| obvious move and it would have answered 419 to every genuine delivery.
*/

Route::get('/', fn () => redirect()->route('login'));

/*
| 🛑 `/login` and `/user/confirm-password` are registered by FORTIFY, not here.
|
| Phase 01 had its own `/login`; Fortify registers one too, and both were live
| and both named `login`, so `route('login')` resolved to whichever registered
| last. The §8.13.3 and §8.13.5 middleware both redirect by name, so the
| destination of a session expiry was a matter of registration order. The same
| collision existed on `password.confirm`.
|
| Fortify owns the routes and the POST handlers; the Inertia views are supplied
| in FortifyServiceProvider.
*/

/*
| 🛑 §8.12.10's dashboard half: mint a handoff code for a documentation origin.
|
| **`auth` but not `tenant`**, deliberately. A reader arrives here from a
| documentation host carrying no organisation of their own — that is the whole
| premise of the handoff — and the organisation is whichever owns the domain
| they came from. App\Http\Controllers\Readers\HandoffController reads across
| organisations to find it and App\Readers\ReaderHandoff re-checks that the
| domain and the project share one, which is the boundary that read crosses to
| establish rather than to ignore.
|
| 🛑 Not under `o/{organisation}`: putting it there would make the documentation
| origin construct a URL naming a tenant, which is a fact it does not have and
| must not guess.
*/
Route::middleware(['auth'])
    ->get('reader/handoff', HandoffController::class)
    ->name('reader.handoff');

/*
| §8.13.4's enrolment page.
|
| 🛑 `auth` and nothing else. It must be reachable by precisely the person the
| MFA gate is holding — see `RequireMfaEnrolment::PERMITTED`, which allows the
| `mfa.` family for that reason. Adding `tenant` here would be wrong twice: the
| requirement is a property of the account rather than of an organisation, and a
| person who has not chosen a tenant yet still has to be able to enrol.
|
| 🛑 No `stepup`. §8.13.5's five-minute window guards mutations; the actual
| mutation is Fortify's `two-factor.enable`, which `config/fortify.php` already
| puts behind `confirmPassword => true`. A second gate here would mean
| confirming a password to reach a page that then asks for it again.
*/
Route::middleware(['auth'])
    ->get('account/two-factor', MfaEnrolmentController::class)
    ->name('mfa.enrol');

/*
| 🛑 §8.12.18's OIDC legs, on the dashboard origin and **unauthenticated**.
|
| The sibling route above is behind `auth` because it mints a handoff code for a
| reader who is already a dashboard user. These two are the other population:
| §8.12.1 keeps `users` and `reader_identities` "physically disjoint", so a
| reader whose identity provider vouches for them never has a dashboard session
| and a route that required one could not serve them.
|
| What stands in for `auth` is not nothing. The start leg resolves a **verified
| domain** and an **active binding** server-side, both from the project rather
| than from a parameter, and the callback leg resolves everything from a stored,
| single-use `state` row — §8.12.18's own requirements, which is why they are
| requirements.
|
| 🛑 One fixed callback path for every binding and every custom domain, which
| is ADR 0008's measurement rather than a convenience: "the identity provider
| never learns which host began the flow", and the spike's control confirmed
| that a per-domain `redirect_uri` is refused unless registered. A
| `{binding}` segment is deliberately absent — which provider guards a project
| is a fact about the project, and a reader who could name one could have DocUp
| conduct a login against another tenant's.
*/
Route::get('_/auth/oidc/start', OidcStartController::class)->name('reader.oidc.start');
Route::get('_/auth/oidc/callback', OidcCallbackController::class)->name('reader.oidc.callback');

/*
| 🛑 §8.12.18's SAML legs, beside OIDC's and for the same reasons: on the
| dashboard origin, unauthenticated, one fixed URL for every binding and every
| custom domain — which ADR 0013 measured on Keycloak 26.0.8 with an
| unregistered ACS refused as the control.
|
| 🛑 **The ACS is a POST, and it is exempt from CSRF.** A SAML response
| arrives as a cross-origin form the identity provider auto-submits, so there is
| no DocUp token to present and no DocUp session cookie in the request; the
| check would refuse every genuine login. What replaces it is stronger than a
| token and is §8.12.18's own requirement: the POST must carry a `RelayState`
| naming a single-use exchange DocUp opened, the response must be signed twice
| by the binding's configured certificate, and its `InResponseTo` must be the
| request id stored in that row. The controller's docblock sets out why a forged
| or captured POST fails.
|
| 🛑 The exemption is **named here, on this one route**, rather than added to
| `validateCsrfTokens(except:)` in `bootstrap/app.php`. An `except` list is a
| pattern list that grows, and a pattern is easy to widen by accident; a
| `withoutMiddleware` on a single route cannot cover a route nobody intended.

| 🛑 **AMENDED (Phase 26b, 2026-11-08): the exemption named the wrong
| class and therefore exempted nothing.**
|
| It read `withoutMiddleware(ValidateCsrfToken::class)`. The `web` group runs
| `PreventRequestForgery`, and `ValidateCsrfToken extends
| PreventRequestForgery` — so the exclusion named the SUBCLASS while the
| group ran the PARENT. `Router::gatherRouteMiddleware()` drops a gathered
| middleware only when its name matches an exclusion or is a subclass of
| one, and the parent is not a subclass of the child. Measured: with the
| HTTP kernel registered, the ACS route still gathered
| `PreventRequestForgery`.
|
| 🛑 **The suite could not see it.** `PreventRequestForgery::handle()`
| skips validation outright when `runningUnitTests()` is true, which it is
| for the whole suite — so Phase 25's ACS tests passed against a route that
| would have refused every genuine identity-provider POST in production with
| a 419. A status-code test can never catch this; the assertion that does is
| structural, over the gathered middleware, in
| `tests/Feature/Ldap/LdapSignInTest.php` — which asserts BOTH halves, this
| route exempt and the credential POST not, because the contrast is the
| requirement.
*/

/*
| 🛑 §8.12.16's credential page, which has no protocol leg because `ldap`
| has no identity provider to visit. The reader types a username and a
| password here and DocUp binds to the directory itself.
|
| 🛑 **On the dashboard origin, and unauthenticated**, for both of the
| reasons OIDC and SAML are. §8.14.12 adds a third that is specific to this
| one: "All authentication MUST redirect to the dashboard host with
| installation branding only, so a tenant-controlled domain can never
| present a DocUp-styled login form." A credential form served from a
| documentation host would be exactly that, and §8.1.4 keeps the origins
| separate so it cannot be.
|
| 🛑 **The POST keeps CSRF**, unlike the SAML ACS beside it. The exemption
| there exists because an assertion arrives as a cross-origin form the
| identity provider auto-submits, with no DocUp token to present; this form
| is served by DocUp to the same origin it posts back to, so the token is
| both available and load-bearing. Without it a third-party page could post
| a reader's cached credentials into a flow whose handoff challenge the
| attacker chose.
|
| 🛑 No `{binding}` and no `{project}` segment, as above: which directory
| guards a project is a fact about the project, and a reader who could name
| one could have DocUp send their password to a directory of their
| choosing. Both legs resolve it through §8.12.3 from the stored domain.
*/
Route::get('_/auth/ldap', [LdapSignInController::class, 'create'])->name('reader.ldap.create');
Route::post('_/auth/ldap', [LdapSignInController::class, 'store'])->name('reader.ldap.store');

Route::get('_/auth/saml/start', SamlStartController::class)->name('reader.saml.start');
Route::post('_/auth/saml/acs', SamlAcsController::class)
    ->withoutMiddleware(PreventRequestForgery::class)
    ->name('reader.saml.acs');

Route::middleware(['auth', 'tenant'])
    ->prefix('o/{organisation}')
    ->name('organisations.')
    ->group(function (): void {
        Route::get('projects', [ProjectController::class, 'index'])->name('projects.index');
        Route::get('projects/{project}', [ProjectController::class, 'show'])->name('projects.show');

        // 🛑 §8.13.5 puts visibility in the 5-minute step-up window: §8.2.10
        // makes this the operator's kill switch, so a session stolen an hour
        // ago must not be able to publish a private project.
        Route::patch('projects/{project}/visibility', ProjectVisibilityController::class)
            ->middleware('stepup:project.visibility.update')
            ->name('projects.visibility.update');

        /*
         * 🛑 §8.12.25's policy simulator — "MUST exist in the UI".
         *
         * A GET, because it is one: the simulation mints nothing and writes
         * nothing (§8.12.25's answer is a read of the same decision a reader's
         * request would get), so the answer is linkable and an operator can
         * paste a surprising result to a colleague who then sees the same
         * surprise. See the controller for why no credential travels in the
         * query string.
         *
         * 🛑 **No step-up**, deliberately, and the asymmetry with the line
         * above is the point: §8.13.5's five-minute window guards *mutations*,
         * and a simulator an operator has to re-authenticate to run is a
         * simulator they run once. The capability check is
         * `project.policy.simulate`, which §12.2 withholds from
         * `project_reader` and `project_writer` precisely so this needs no
         * second gate.
         */
        Route::get('projects/{project}/policy/simulate', PolicySimulatorController::class)
            ->name('projects.policy.simulate');

        /*
         * 🛑 §8.12.20's break-glass read override.
         *
         * A POST, although the override only ever *reads* documentation: it
         * writes a grant, raises an operator alert and consumes one of three
         * hourly activations. A GET would make it reachable from a link, which
         * is the one shape this button must never have.
         *
         * 🛑 `stepup` with no capability name, which {@see \App\Http\Middleware\RequireRecentAuthentication::windowFor()}
         * resolves to the ROUTINE fifteen minutes — so the five-minute
         * window §8.12.20 actually needs is enforced by {@see \App\Access\BreakGlass}
         * reading the session stamp itself. The middleware is here for the
         * redirect to the confirmation page, which is UX the service cannot
         * provide; it is not the control.
         */
        Route::post('projects/{project}/break-glass', [BreakGlassController::class, 'store'])
            ->middleware('stepup:5')
            ->name('projects.break-glass.store');

        /*
         * 🛑 No step-up on the close, deliberately: closing an override
         * NARROWS access, and a control harder to turn off than on is one
         * nobody turns off.
         */
        Route::delete('break-glass/{grant}', [BreakGlassController::class, 'destroy'])
            ->name('break-glass.destroy');
    });

/*
| The dashboard's own API reads.
|
| 🛑 `api/v3`, not `api/v1`. Phase 02 created these under v1 before anything had
| read §8.21.1, which names "REST API v3" — and the number is not cosmetic:
| §3 and §20.4 make RTD compatibility a goal, so an imported CI script or
| importer looking for a v3 path should find the shape it expects where it
| expects it. Shipping v1 and v3 side by side would have been two public
| contracts on day one, which §8.1.11 is precisely about not doing. Corrected
| in Phase 03, while the only callers are this repository's own tests.
|
| These carry session authentication and a tenant in the path; the Phase 03
| publish endpoints under the same prefix carry a bearer token and take their
| tenant from it (§8.21.2, §8.9.4). One API surface, two credential types — the
| dashboard is a first-party client, not a third-party one.
*/
Route::middleware(['auth', 'tenant'])
    ->prefix('api/v3/organisations/{organisation}')
    ->name('api.v3.organisations.')
    ->group(function (): void {
        Route::get('projects', [ApiProjectController::class, 'index'])->name('projects.index');
        Route::get('projects/{project}', [ApiProjectController::class, 'show'])->name('projects.show');

        /*
         * §8.6's version list. 🛑 `listed` is what decides membership —
         * §8.6.2's "a hidden version serves by direct URL but is absent
         * from the flyout, sitemap, `llms.txt` and search", of which this
         * is the first surface to exist.
         */
        Route::get('projects/{project}/versions', [ApiProjectVersionController::class, 'index'])
            ->name('projects.versions.index');
    });
