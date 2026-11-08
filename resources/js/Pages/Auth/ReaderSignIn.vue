<script setup>
// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0
//
// §8.12.16's reader credential page, for the `ldap` driver.
//
// 🛑 NO PROJECT OR ORGANISATION BRANDING. §8.14.12: "Pages that accept
// credentials MUST carry no project or organisation branding. All
// authentication MUST redirect to the dashboard host with installation
// branding only, so a tenant-controlled domain can never present a
// DocUp-styled login form." `installationName` and `directory` are the only
// names on this page, and both are the operator's. Phase 27 owns the
// enforcement of that rule; this page is written to it now so it is not one
// that has to be fixed then.
//
// 🛑 The form carries NO domain, challenge or return path. Those live in the
// server-side session — see LdapSignInController — so the only reader-chosen
// values posted with a password are the username and the password. A hidden
// field naming the domain would be a reader-chosen answer to "which directory
// does this password go to".
//
// 🛑 One message for every failure. `failed` is a single sentence whether the
// password was wrong, the username unknown, the directory down or the client
// locked out: anything more specific would enumerate the operator's employee
// directory to anyone who can reach this page.
defineProps({
  installationName: { type: String, required: true },
  // The binding's own label, which §8.12.4 makes installation-scoped.
  label: { type: String, required: true },
  failed: { type: Boolean, default: false },
  csrfToken: { type: String, required: true },
  t: { type: Object, required: true },
})
</script>

<template>
  <main class="mx-auto max-w-sm p-8">
    <p class="text-sm text-gray-500">{{ installationName }}</p>
    <h1 class="mt-1 text-xl font-semibold">{{ t.title }}</h1>
    <p class="mt-2 text-sm text-gray-600">
      {{ t.intro.replace(':directory', label) }}
    </p>

    <!--
      🛑 `role="alert"` and not `aria-live="assertive"`: the banner is present
      from first paint on a failed attempt, so a live region would announce
      nothing. A reader using a screen reader is the one most likely to have
      mistyped.
    -->
    <p v-if="failed" role="alert" class="mt-4 rounded bg-red-50 px-3 py-2 text-sm text-red-800">
      {{ t.failed }}
    </p>

    <!--
      A plain form POST rather than an Inertia visit, deliberately: the
      successful response is a 302 to another origin's handoff URL, which
      Inertia's XHR cannot follow. The CSRF token is the one the `web` group
      put in the session.
    -->
    <form class="mt-6 space-y-4" method="post" action="/_/auth/ldap">
      <input type="hidden" name="_token" :value="csrfToken" />

      <label class="block">
        <span class="text-sm font-medium">{{ t.username }}</span>
        <input type="text" name="username" autocomplete="username" required autofocus
               maxlength="256" class="mt-1 block w-full rounded border px-3 py-2" />
      </label>

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
