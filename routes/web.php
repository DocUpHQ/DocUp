<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Http\Controllers\Api\ProjectController as ApiProjectController;
use App\Http\Controllers\ProjectController;
use App\Http\Controllers\ProjectVisibilityController;
use Illuminate\Support\Facades\Route;
use Inertia\Inertia;

/*
| Phase 01 served one page: the login form. Phase 02 adds the organisation and
| project surfaces behind authentication.
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
| The dashboard API. Same middleware, same 404 semantics; a separate prefix so
| the §8.1.11 public-contract versioning has somewhere to live.
*/
Route::middleware(['auth', 'tenant'])
    ->prefix('api/v1/organisations/{organisation}')
    ->name('api.v1.organisations.')
    ->group(function (): void {
        Route::get('projects', [ApiProjectController::class, 'index'])->name('projects.index');
        Route::get('projects/{project}', [ApiProjectController::class, 'show'])->name('projects.show');
    });
