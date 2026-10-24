<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

/*
|------------------------------------------------------------------------------
| Broadcasting — SPEC 8.5.22's OPTIONAL WebSocket profile
|------------------------------------------------------------------------------
| 🛑 "Polling MUST be the default and the only thing in the core compose file;
| WebSocket streaming MUST be an optional profile."
|
| So the default here is `null`: an installation that does nothing broadcasts
| nothing, runs no second process and opens no second port. SPEC 19/22 gives
| the reasoning in full - a long-running process, a second exposed port, a
| Redis-only scaling dependency and a 1,024-FD ceiling, for builds measured in
| minutes.
|
| 🛑 The profile is a SECOND TRANSPORT OVER THE SAME CONTRACT, never a second
| contract. `BuildLogAppended` carries a cursor and nothing else; a client that
| receives it fetches the page it was already entitled to through
| `GET /api/v3/builds/{id}/log?from=<seq>`. Pushing the lines themselves would
| mean two serialisations of one log that could disagree - and the one that
| disagreed would be the one nobody tested, because polling is what the suite
| exercises.
|
| To enable it: `composer require laravel/reverb`, set
| BROADCAST_CONNECTION=reverb, and run the compose.websocket.yaml overlay.
*/

return [

    /*
     * 🛑 `?:` rather than a default argument, and the reason is a trap
     * worth naming: `BROADCAST_CONNECTION=null` in an environment file is
     * parsed by Dotenv as PHP **null**, not as the string "null" — so
     * `env('BROADCAST_CONNECTION', 'null')` returns null and the fallback
     * never fires. Laravel then cannot resolve a connection at all, and
     * the failure surfaces as a broadcast manager exception from
     * somewhere unrelated. Found by the test below.
     */
    'default' => env('BROADCAST_CONNECTION') ?: 'null',

    'connections' => [

        /*
         * Laravel Reverb. Absent from the core compose file by design; see
         * compose.websocket.yaml, which is the whole of the profile.
         */
        'reverb' => [
            'driver' => 'reverb',
            'key' => env('REVERB_APP_KEY'),
            'secret' => env('REVERB_APP_SECRET'),
            'app_id' => env('REVERB_APP_ID'),
            'options' => [
                'host' => env('REVERB_HOST'),
                'port' => (int) env('REVERB_PORT', 443),
                'scheme' => env('REVERB_SCHEME', 'https'),

                /*
                 * 🛑 TLS verification stays on. A WebSocket carrying build
                 * logs carries paths, dependency versions and sometimes
                 * content (SPEC 8.5.22's own words), and a profile that
                 * shipped with verification off would be the convenience
                 * that nobody turns back on.
                 */
                'useTLS' => env('REVERB_SCHEME', 'https') === 'https',
            ],
        ],

        /*
         * The default. Nothing is broadcast, nothing listens, and the
         * offset-addressed poll of SPEC 8.5.22 is the only transport.
         */
        'null' => [
            'driver' => 'null',
        ],

        /*
         * For development: broadcasts are written to the application log so
         * the event can be seen without standing a server up. Never a
         * production setting - SPEC 15.1 requires a redaction processor on
         * application logs precisely because things end up there.
         */
        'log' => [
            'driver' => 'log',
        ],
    ],
];
