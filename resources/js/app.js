// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

import { createApp, h } from 'vue'
import { createInertiaApp } from '@inertiajs/vue3'

// SPEC 11.1: Inertia 3, Vue 3.5, Tailwind 4, Vite 8.
//
// Note on the baseline: SPEC 11.1 suggested the official Laravel Vue starter kit
// as the obvious starting point. Phase 01 found it pinned to Laravel ^12 and
// Inertia ^2, so this stack is wired explicitly against Laravel 13 / Inertia 3
// instead. See the Phase 01 build-log entry.
createInertiaApp({
    title: (title) => (title ? `${title} · DocUp` : 'DocUp'),

    resolve: (name) => {
        const pages = import.meta.glob('./Pages/**/*.vue', { eager: true })
        const page = pages[`./Pages/${name}.vue`]

        if (!page) {
            throw new Error(`Inertia page not found: ${name}`)
        }

        return page
    },

    setup({ el, App, props, plugin }) {
        createApp({ render: () => h(App, props) })
            .use(plugin)
            .mount(el)
    },

    progress: { color: '#2563eb' },
})
