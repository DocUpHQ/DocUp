// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from 'vite'
import laravel from 'laravel-vite-plugin'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
    plugins: [
        laravel({
            /*
             * 🛑 `chrome.css` is a second entry, not part of app.css, and
             * SPEC 8.14.4 is why: it is "one bundle" shared by every project
             * and it is loaded inside SPEC 8.15.5's closed shadow root, where
             * the dashboard's stylesheet does not reach. Compiled here, once,
             * at release time — never per tenant and never on a request path.
             */
            input: ['resources/css/app.css', 'resources/css/chrome.css', 'resources/js/app.js'],
            refresh: true,
        }),
        vue({
            template: { transformAssetUrls: { base: null, includeAbsolute: false } },
        }),
        tailwindcss(),
    ],
})
