<!--
  SPDX-FileCopyrightText: 2026 The DocUp contributors
  SPDX-License-Identifier: Apache-2.0

  The Phase 01 login page. It renders and it is localised; it does NOT
  authenticate. Sessions, Fortify hardening, MFA and step-up re-authentication
  are Phase 02 (SPEC 8.13.3-8.13.5), and Phase 01's scope note is explicit that
  no domain model exists yet - there are no users to log in.

  🛑 SPEC 8.14.12: a credential-entry page carries INSTALLATION branding only,
  never a project's or an organisation's. A tenant-controlled domain must never
  be able to present a DocUp-styled login form. There is deliberately no
  per-project theming hook on this component.
-->
<script setup>
import { Head } from '@inertiajs/vue3'

defineProps({
    installationName: { type: String, default: 'DocUp' },
    locale: { type: String, default: 'en' },
    t: { type: Object, required: true },
})
</script>

<template>
    <Head :title="t.title" />

    <div class="flex min-h-screen items-center justify-center bg-slate-50 px-4 dark:bg-slate-950">
        <main class="w-full max-w-sm">
            <div class="mb-8 text-center">
                <h1 class="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-50">
                    {{ installationName }}
                </h1>
                <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">
                    {{ t.subtitle }}
                </p>
            </div>

            <div
                class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900"
            >
                <form class="space-y-4" @submit.prevent>
                    <div>
                        <label
                            for="email"
                            class="block text-sm font-medium text-slate-700 dark:text-slate-300"
                        >
                            {{ t.email }}
                        </label>
                        <input
                            id="email"
                            type="email"
                            autocomplete="username"
                            class="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-slate-900 shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
                        />
                    </div>

                    <div>
                        <label
                            for="password"
                            class="block text-sm font-medium text-slate-700 dark:text-slate-300"
                        >
                            {{ t.password }}
                        </label>
                        <input
                            id="password"
                            type="password"
                            autocomplete="current-password"
                            class="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 text-slate-900 shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
                        />
                    </div>

                    <button
                        type="submit"
                        disabled
                        class="w-full rounded-md bg-blue-600 px-3 py-2 text-sm font-semibold text-white shadow-sm disabled:cursor-not-allowed disabled:opacity-60"
                    >
                        {{ t.submit }}
                    </button>
                </form>

                <p class="mt-4 text-center text-xs text-slate-400 dark:text-slate-500">
                    {{ t.phase_notice }}
                </p>
            </div>

            <p class="mt-6 text-center text-xs text-slate-400 dark:text-slate-500">
                {{ t.locale_label }}: <code>{{ locale }}</code>
            </p>
        </main>
    </div>
</template>
