<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use Laravel\Fortify\Features;

return [

    /*
    |--------------------------------------------------------------------------
    | Fortify Guard
    |--------------------------------------------------------------------------
    |
    | Here you may specify which authentication guard Fortify will use while
    | authenticating users. This value should correspond with one of your
    | guards that is already present in your "auth" configuration file.
    |
    */

    'guard' => 'web',

    /*
    |--------------------------------------------------------------------------
    | Fortify Password Broker
    |--------------------------------------------------------------------------
    |
    | Here you may specify which password broker Fortify can use when a user
    | is resetting their password. This configured value should match one
    | of your password brokers setup in your "auth" configuration file.
    |
    */

    'passwords' => 'users',

    /*
    |--------------------------------------------------------------------------
    | Username / Email
    |--------------------------------------------------------------------------
    |
    | This value defines which model attribute should be considered as your
    | application's "username" field. Typically, this might be the email
    | address of the users but you are free to change this value here.
    |
    | Out of the box, Fortify expects forgot password and reset password
    | requests to have a field named 'email'. If the application uses
    | another name for the field you may define it below as needed.
    |
    */

    'username' => 'email',

    'email' => 'email',

    /*
    |--------------------------------------------------------------------------
    | Lowercase Usernames
    |--------------------------------------------------------------------------
    |
    | This value defines whether usernames should be lowercased before saving
    | them in the database, as some database system string fields are case
    | sensitive. You may disable this for your application if necessary.
    |
    */

    'lowercase_usernames' => true,

    /*
    |--------------------------------------------------------------------------
    | Home Path
    |--------------------------------------------------------------------------
    |
    | Here you may configure the path where users will get redirected during
    | authentication or password reset when the operations are successful
    | and the user is authenticated. You are free to change this value.
    |
    */

    // There is no /home in DocUp. After authentication a person belongs to
    // one or more organisations, and which one is a decision the dashboard
    // makes; until that surface exists, the login page is the honest landing.
    'home' => '/login',

    /*
    |--------------------------------------------------------------------------
    | Fortify Routes Prefix / Subdomain
    |--------------------------------------------------------------------------
    |
    | Here you may specify which prefix Fortify will assign to all the routes
    | that it registers with the application. If necessary, you may change
    | subdomain under which all of the Fortify routes will be available.
    |
    */

    'prefix' => '',

    'domain' => null,

    /*
    |--------------------------------------------------------------------------
    | Fortify Routes Middleware
    |--------------------------------------------------------------------------
    |
    | Here you may specify which middleware Fortify will assign to the routes
    | that it registers with the application. If necessary, you may change
    | these middleware but typically this provided default is preferred.
    |
    */

    'middleware' => ['web'],

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting
    |--------------------------------------------------------------------------
    |
    | By default, Fortify will throttle logins to five requests per minute for
    | every email and IP address combination. However, if you would like to
    | specify a custom rate limiter to call then you may specify it here.
    |
    */

    'limiters' => [
        'login' => 'login',
        'two-factor' => 'two-factor',
        'passkeys' => 'passkeys',
    ],

    /*
    |--------------------------------------------------------------------------
    | Register View Routes
    |--------------------------------------------------------------------------
    |
    | Here you may specify if the routes returning views should be disabled as
    | you may not need them when building your own application. This may be
    | especially true if you're writing a custom single-page application.
    |
    */

    'views' => true,

    /*
    |--------------------------------------------------------------------------
    | Passkeys
    |--------------------------------------------------------------------------
    |
    | These settings configure Fortify's passkey (WebAuthn) support. Passkeys
    | allow users to sign in without needing to remember credentials since
    | they use public-key cryptography - making them immune to breaches.
    |
    */

    'passkeys' => [
        'relying_party_id' => parse_url(config('app.url'), PHP_URL_HOST),
        'allowed_origins' => [config('app.url')],
        'timeout' => 60000,
    ],

    /*
    |--------------------------------------------------------------------------
    | Features
    |--------------------------------------------------------------------------
    |
    | Some of the Fortify features are optional. You may disable the features
    | by removing them from this array. You're free to only remove some of
    | these features or you can even remove all of these if you need to.
    |
    */

    'features' => [
        /*
         * 🛑 Registration is OFF, and that is a product decision, not an
         * oversight.
         *
         * DocUp is self-hosted and §8.2.4 makes invitations the way people
         * join: single-use, hashed, email-bound, with the role pre-staged.
         * Open registration would let anyone with the URL create an account on
         * someone else's installation — and because §8.13.1's roles are
         * assigned rather than claimed, those accounts would be inert but
         * real: a growing list of unknown identities on a private portal.
         */
        // Features::registration(),

        Features::resetPasswords(),

        // Phase 02 has no mail templates of its own yet (§8.18). Enabling
        // verification now would hold every invited member at an unsendable
        // email.
        // Features::emailVerification(),

        Features::updateProfileInformation(),
        Features::updatePasswords(),

        /*
         * §8.13.4: MFA via TOTP, enforceable per installation and per
         * organisation, required above `project_writer`.
         *
         * `confirm => true` so a secret is not treated as "MFA enabled" until
         * a code has been verified — otherwise someone who abandons the
         * QR-code screen locks themselves out, and the only fix is an operator
         * disabling the control.
         *
         * `confirmPassword => true` because enrolling or disabling MFA is
         * itself a sensitive mutation; §8.13.5 would put it in the 5-minute
         * window.
         */
        Features::twoFactorAuthentication([
            'confirm' => true,
            'confirmPassword' => true,
        ]),

        /*
         * 🛑 Passkeys are OFF pending §18.
         *
         * §8.13.4 says "with passkeys where the library proves
         * production-ready (§18)" — an explicitly UNVERIFIED assumption, and
         * CLAUDE.md rule 1 requires it verified before a phase rests on it.
         * Fortify bundles laravel/passkeys and would have enabled it by
         * default; enabling an unproven library on the authentication path is
         * precisely what §18 exists to prevent. The published
         * create_passkeys_table migration was removed for the same reason: an
         * unused table in the schema reads as a feature that exists.
         *
         * Turn this on when §18 records a pass, not before.
         */
        // Features::passkeys(),
    ],

];
