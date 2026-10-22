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

    <form class="mt-6 space-y-4" method="post" action="/reset-password">
      <label class="block">
        <span class="text-sm font-medium">{{ t.password }}</span>
        <input type="password" name="password" autocomplete="new-password" required
               class="mt-1 block w-full rounded border px-3 py-2" />
      </label>
      <label class="block">
        <span class="text-sm font-medium">{{ t.confirm }}</span>
        <input type="password" name="password_confirmation" autocomplete="new-password" required
               class="mt-1 block w-full rounded border px-3 py-2" />
      </label>

      <button type="submit" class="w-full rounded bg-gray-900 px-3 py-2 text-white">{{ t.submit }}</button>
    </form>
  </main>
</template>
