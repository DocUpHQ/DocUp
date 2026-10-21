<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

return [

    /*
    |---------------------------------------------------------------------------
    | Default hash driver
    |---------------------------------------------------------------------------
    */
    'driver' => env('HASH_DRIVER', 'argon2id'),

    /*
    |---------------------------------------------------------------------------
    | Argon2id parameters (SPEC 8.12.16)
    |---------------------------------------------------------------------------
    | 🛑 This file exists specifically to override a weak framework default.
    | Laravel's ArgonHasher defaults to m=1024 KiB, roughly 19x BELOW the OWASP
    | password-storage floor of 19456 KiB (19 MiB) at t=2, p=1. Phase 00 verified
    | the default is still 1024 on the current release.
    |
    | Raising it here, rather than relying on the default, is why SPEC 9.3.8
    | lists it as a framework landmine to close explicitly. A test asserts these
    | values do not regress.
    */
    'argon' => [
        'memory' => (int) env('ARGON_MEMORY', 19456),
        'threads' => (int) env('ARGON_THREADS', 1),
        'time' => (int) env('ARGON_TIME', 2),
        'verify' => true,
    ],

    'bcrypt' => [
        'rounds' => (int) env('BCRYPT_ROUNDS', 12),
        'verify' => true,
        'limit' => null,
    ],

    'rehash_on_login' => true,

];
