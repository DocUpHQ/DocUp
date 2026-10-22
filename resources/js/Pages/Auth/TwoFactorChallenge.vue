<script setup>
// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0
//
// Plain by intention: §8.14 makes branding a closed registry of design tokens
// in Phase 15, and anything invented here would be unpicked then. The forms
// post to Fortify's own handlers, which own the password check, the TOTP
// verification and the §8.13.5 throttling.
defineProps({
  installationName: { type: String, required: true },
  t: { type: Object, required: true },
})
</script>

<template>
  <main class="mx-auto max-w-sm p-8">
    <h1 class="text-xl font-semibold">{{ t.title }}</h1>
    <p class="mt-2 text-sm text-gray-600">{{ t.intro }}</p>

    <form class="mt-6 space-y-4" method="post" action="/two-factor-challenge">
      <label class="block">
        <span class="text-sm font-medium">{{ t.code }}</span>
        <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required
               class="mt-1 block w-full rounded border px-3 py-2" />
      </label>

      <details class="text-sm">
        <summary class="cursor-pointer text-gray-600">{{ t.recovery_prompt }}</summary>
        <label class="mt-2 block">
          <span class="text-sm font-medium">{{ t.recovery_code }}</span>
          <input type="text" name="recovery_code" autocomplete="one-time-code"
                 class="mt-1 block w-full rounded border px-3 py-2" />
        </label>
      </details>

      <button type="submit" class="w-full rounded bg-gray-900 px-3 py-2 text-white">{{ t.submit }}</button>
    </form>
  </main>
</template>
