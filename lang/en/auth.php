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

    /*
    | §8.13.5 step-up re-authentication. 🛑 §9.5.2: every user-visible string
    | comes from a message file, from the first string onward.
    */
    'confirm' => [
        'title' => 'Confirm your password',
        'intro' => 'This action is sensitive, so please confirm your password to continue.',
        'password' => 'Password',
        'submit' => 'Confirm',
    ],

    /*
    | §8.13.4 two-factor challenge.
    */
    'two_factor' => [
        'title' => 'Two-factor authentication',
        'intro' => 'Enter the code from your authenticator app.',
        'code' => 'Authentication code',
        'recovery_prompt' => 'Use a recovery code instead',
        'recovery_code' => 'Recovery code',
        'submit' => 'Continue',
    ],

    'forgot' => [
        'title' => 'Reset your password',
        'intro' => 'We will email you a link to choose a new password.',
        'email' => 'Email address',
        'submit' => 'Send reset link',
    ],

    'reset' => [
        'title' => 'Choose a new password',
        'password' => 'New password',
        'confirm' => 'Confirm new password',
        'submit' => 'Save password',
    ],

    'failed' => 'Those credentials do not match our records.',
    'throttle' => 'Too many attempts. Please try again in :seconds seconds.',

];
