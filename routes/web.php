<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Inertia\Inertia;

/*
| Phase 01 serves one page: the login form (SPEC 17, Phase 01 exit criteria).
| It renders and it is localised. It does not authenticate - there is no domain
| model yet, which Phase 01's scope note states explicitly.
*/

Route::get('/', fn () => redirect()->route('login'));

Route::get('/login', fn () => Inertia::render('Auth/Login', [
    'installationName' => config('app.name', 'DocUp'),
    'locale' => app()->getLocale(),
    // SPEC 9.5.2: every UI string comes from a message file, from the first
    // string onward. Nothing user-visible is hard-coded in a component.
    't' => __('auth.login'),
]))->name('login');
