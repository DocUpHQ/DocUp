<script setup>
// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0
//
// §8.13.5 step-up. The form posts nowhere yet: Fortify owns the confirmation
// endpoint and arrives with the rest of the authentication scaffolding. What
// matters now is that the middleware has somewhere real to redirect to —
// redirecting to a missing route would turn a security control into a 500.
defineProps({
  installationName: { type: String, required: true },
  t: { type: Object, required: true },
})
</script>

<template>
  <main class="mx-auto max-w-sm p-8">
    <h1 class="text-xl font-semibold">{{ t.title }}</h1>
    <p class="mt-2 text-sm text-gray-600">{{ t.intro }}</p>

    <form class="mt-6 space-y-4" method="post" action="/password/confirm">
      <label class="block">
        <span class="text-sm font-medium">{{ t.password }}</span>
        <input type="password" name="password" autocomplete="current-password" required
               class="mt-1 block w-full rounded border px-3 py-2" />
      </label>

      <button type="submit" class="w-full rounded bg-gray-900 px-3 py-2 text-white">
        {{ t.submit }}
      </button>
    </form>
  </main>
</template>
