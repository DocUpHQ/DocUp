<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Http\Controllers\Api\ProjectController as ApiProjectController;
use App\Http\Controllers\Api\ProjectVersionController as ApiProjectVersionController;
use App\Http\Controllers\Health\LiveController;
use App\Http\Controllers\Health\ReadyController;
use App\Http\Controllers\Health\SelfTestController;
use App\Http\Controllers\ProjectController;
use App\Http\Controllers\ProjectVisibilityController;
use App\Http\Controllers\SchemaController;
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
