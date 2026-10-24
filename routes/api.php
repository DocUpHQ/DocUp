<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Http\Controllers\Api\BuildCancelController;
use App\Http\Controllers\Api\BuildController;
use App\Http\Controllers\Api\BuildLogController;
use App\Http\Controllers\Api\VersionPinController;
use App\Http\Controllers\Api\VersionRollbackController;
use App\Http\Controllers\Api\VersionUploadController;
use Illuminate\Support\Facades\Route;

/*
|------------------------------------------------------------------------------
| REST API v3 (SPEC 8.21)
|------------------------------------------------------------------------------
| 🛑 v3, not v1. SPEC 8.21.1 names "REST API v3" and the version number is part
| of the Read the Docs compatibility story (SPEC 3, SPEC 20.4): an importer and a
| CI script written against RTD's v3 should find the shape it expects at the
| path it expects. Starting at v1 would have been a tidier-looking decision that
| made every migrated pipeline rewrite its URLs.
|
| Phase 03 serves only the direct artifact upload of SPEC 8.21.6 and the SPEC
| 8.8.5 pointer controls. The rest of SPEC 8.21.1's floor arrives with the
| features it describes - SPEC 4.3 forbids an endpoint for a thing that does not
| exist yet.
|
| 🛑 No tenant appears in these paths. The token carries the organisation (see
| AuthenticateApiToken), which is what SPEC 8.9.4 requires: no request header or
| path segment is ever trusted to resolve a tenant.
*/

Route::prefix('api/v3')
    ->middleware(['api.token', 'throttle:api'])
    ->group(function (): void {
        Route::prefix('projects/{project}/versions/{version}')->group(function (): void {
            /*
             * SPEC 8.21.6's direct artifact upload. POST rather than PUT: each
             * upload creates a new build, so the call is not idempotent and
             * must not advertise itself as such - a CI system retrying a PUT on
             * a timeout would silently produce two builds either way, but with
             * POST it knows that is what it did.
             */
            Route::post('uploads', [VersionUploadController::class, 'store'])
                ->middleware('token.can:project.version.publish')
                ->name('api.v3.versions.uploads.store');

            Route::post('rollback', VersionRollbackController::class)
                ->middleware('token.can:project.version.rollback')
                ->name('api.v3.versions.rollback');

            /*
             * Clearing a pin is part of the rollback decision, so it takes the
             * same capability. SPEC 8.8.5 says the pin blocks automatic
             * republication "until a human unpins" - whoever may withdraw
             * content is who may decide it is safe to publish again.
             */
            Route::delete('pin', [VersionPinController::class, 'destroy'])
                ->middleware('token.can:project.version.rollback')
                ->name('api.v3.versions.unpin');
        });

        /*
         * §8.5.23's cancellation. Inside the credentialed group, because
         * stopping somebody's build is a mutation and the anonymous
         * reader of §8.5.22 has no business doing it — the controller
         * asserts the credential again rather than relying on this
         * grouping alone.
         */
        Route::post('builds/{build}/cancel', BuildCancelController::class)
            ->middleware('token.can:project.version.publish')
            ->name('api.v3.builds.cancel');
    });

/*
|------------------------------------------------------------------------------
| §8.5.22's build-log contract
|------------------------------------------------------------------------------
| 🛑 OUTSIDE the credentialed group, and deliberately so. §8.5.22 makes
| build-log visibility for anonymous readers of public projects a per-project
| setting — so the endpoint has to be reachable without a credential in order
| to then refuse almost everybody. `api.token:optional` accepts no credential
| and still rejects a WRONG one, and `BuildAccess` applies the two policies.
|
| The build state endpoint shares the same rule: a reader allowed to see a
| log should be able to tell whether the build that produced it finished, and
| splitting them would mean polling a 404 to find out.
*/
Route::prefix('api/v3')
    ->middleware(['api.token:optional', 'throttle:api'])
    ->group(function (): void {
        Route::get('builds/{build}', BuildController::class)->name('api.v3.builds.show');
        Route::get('builds/{build}/log', BuildLogController::class)->name('api.v3.builds.log');
    });
