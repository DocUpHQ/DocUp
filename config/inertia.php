<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

/*
|------------------------------------------------------------------------------
| Inertia — the page directory, and nothing else
|------------------------------------------------------------------------------
| 🛑 This file exists to correct one path, and it is a path whose default is
| wrong on exactly half the platforms this project is developed on.
|
| `inertiajs/inertia-laravel` defaults `pages.paths` to
| `resource_path('js/pages')` — **lowercase**. This repository uses Laravel's
| own convention, `resources/js/Pages`, which is what `resources/js/app.js`
| resolves components against and what every page has been in since Phase 02.
|
| 🛑 The consequence was invisible until Phase 26a, and the shape of its
| invisibility is the reason this comment is long. `assertInertia(...)` resolves
| the component as a file under `pages.paths` when
| `inertia.testing.ensure_pages_exist` is true, which it is by default. On a
| case-insensitive filesystem — Windows, and macOS as shipped — asking for
| `js/pages` finds `js/Pages`, so the assertion passes. On Linux it does not, so
| the assertion fails with "Inertia page component file [X] does not exist" for
| a file that plainly does exist.
|
| So the first test in this repository to use `assertInertia` passed on a
| developer's machine and failed in CI, and it would have done so for **any**
| page. Nothing was wrong with the page, the route or the controller.
|
| 🛑 Only `pages` is restated here. Laravel merges a published package
| configuration over the package's own at the **top level**, so every other key
| — `ssr`, `testing`, `history`, `devtools` — keeps the package default and
| follows the package when it changes. Restating the whole file would freeze
| defaults this project has no opinion about, which is how a published config
| file becomes a thing nobody dares upgrade.
|
| `extensions` is repeated because it lives inside `pages` and a partial `pages`
| array would replace it with nothing. `ensure_pages_exist` is the package's own
| default (false): it governs the **runtime** check, and this project does not
| want a missing component to become a 500 in production when the client-side
| router would report it more usefully.
*/

return [

    'pages' => [

        'ensure_pages_exist' => false,

        'paths' => [

            resource_path('js/Pages'),

        ],

        'extensions' => [

            'js',
            'jsx',
            'svelte',
            'ts',
            'tsx',
            'vue',

        ],

    ],

];
