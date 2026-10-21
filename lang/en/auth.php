<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

/*
| SPEC 9.5.2: all UI strings live in message files from the first string, and the
| dashboard locale is kept strictly separate from documentation-content locale
| routing (SPEC 8.6.12) - this file is the dashboard's, not a project's.
*/

return [

    'login' => [
        'title' => 'Sign in',
        'subtitle' => 'Sign in to the documentation portal',
        'email' => 'Email address',
        'password' => 'Password',
        'submit' => 'Sign in',
        'phase_notice' => 'Authentication arrives in Phase 02.',
        'locale_label' => 'Locale',
    ],

    'failed' => 'Those credentials do not match our records.',
    'throttle' => 'Too many attempts. Please try again in :seconds seconds.',

];
