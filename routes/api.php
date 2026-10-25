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
use App\Http\Controllers\WebhookController;
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

/*
|------------------------------------------------------------------------------
| §8.19.3's incoming provider webhooks
|------------------------------------------------------------------------------
| 🛑 **One route, and it names an integration.** The id is the only thing the
| URL carries, and it proves nothing on its own: `WebhookIngestor` unseals
| that integration's secret and verifies the HMAC over the raw body before
| anything else happens. An unknown integration and a bad signature answer
| the same 401, so the URL cannot be used to enumerate which integrations
| exist.
|
| 🛑 **There is no unsigned endpoint, generic or otherwise.** §8.19.3: "An
| **unsigned** generic webhook endpoint MUST NOT exist — Read the Docs ships
| one and it is a build-trigger oracle." A *signed* generic integration DOES
| exist — §8.5.3 lists "generic webhook" among the eight trigger kinds — and
| it arrives on this same route carrying `X-DocUp-Signature`.
| `tests/Feature/Webhooks/WebhookRouteTest.php` asserts the absence by
| walking the route table, because an absence is the one thing a test of the
| routes that DO exist cannot prove.
|
| Here rather than in routes/web.php because that file is wrapped in the
| `web` group, whose CSRF validation would answer 419 to every genuine
| delivery — a provider has no session and cannot obtain a token.
|
| No `api.token`: the signature IS the credential, and a bearer token the
| provider does not have would make the endpoint unreachable. The throttle
| is §9.4.5's "webhook ingestion per integration" limiter.
*/
Route::post('_/webhook/{integration}', WebhookController::class)
    ->middleware('throttle:webhooks')
    ->whereUuid('integration')
    ->name('webhook.deliver');
