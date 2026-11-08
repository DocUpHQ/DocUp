<script setup>
// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0
import { ref } from 'vue'
import { router } from '@inertiajs/vue3'

const props = defineProps({
  // Whether SPEC 8.13.4 obliges this person, as opposed to their enrolling by
  // choice. The page says so, because being held out of your own dashboard
  // with no stated reason is how a person ends up asking an administrator a
  // question the installation could have answered.
  required: { type: Boolean, default: false },
  enrolled: { type: Boolean, default: false },

  // SPEC 12.1's role names — only the ones that oblige enrolment. Listing all
  // of them would invite the reader to work out which, and they would guess
  // wrong.
  because: { type: Array, default: () => [] },
  installationWide: { type: Boolean, default: false },
})

// 🛑 Nothing here generates a secret. Fortify's own endpoints do all of it;
// this page posts to them. The secret generation, the window tolerance, the
// recovery codes and the challenge throttle are a security surface with
// known-good answers, and re-implementing any of them here would be the second
// implementation of the part nobody should write twice.
const qr = ref('')
const secret = ref('')
const recovery = ref([])
const code = ref('')
const error = ref('')
const working = ref(false)

async function begin() {
  working.value = true
  error.value = ''

  try {
    // Fortify's `two-factor.enable`. `confirm => true` in config/fortify.php
    // means this issues a secret and does NOT count as enrolment until a code
    // has been verified below — so somebody who closes the tab here is not
    // locked out with a secret no authenticator holds.
    await send('/user/two-factor-authentication', 'POST')

    const [qrResponse, secretResponse] = await Promise.all([
      fetch('/user/two-factor-qr-code', { headers: { Accept: 'application/json' } }),
      fetch('/user/two-factor-secret-key', { headers: { Accept: 'application/json' } }),
    ])

    qr.value = (await qrResponse.json()).svg
    secret.value = (await secretResponse.json()).secretKey
  } catch (e) {
    error.value = e.message
  } finally {
    working.value = false
  }
}

async function confirm() {
  working.value = true
  error.value = ''

  try {
    await send('/user/confirmed-two-factor-authentication', 'POST', { code: code.value })

    const codes = await fetch('/user/two-factor-recovery-codes', {
      headers: { Accept: 'application/json' },
    })

    recovery.value = await codes.json()
  } catch (e) {
    error.value = e.message
  } finally {
    working.value = false
  }
}

async function send(url, method, body) {
  const response = await fetch(url, {
    method,
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      // The session cookie carries the CSRF token; Laravel's `web` group reads
      // this header for an XHR.
      'X-XSRF-TOKEN': decodeURIComponent(
        (document.cookie.match(/XSRF-TOKEN=([^;]+)/) ?? [])[1] ?? '',
      ),
    },
    body: body ? JSON.stringify(body) : undefined,
  })

  if (!response.ok) {
    const payload = await response.json().catch(() => ({}))

    // 🛑 Fortify's own message, not one of ours. It distinguishes a wrong code
    // from an expired window from a rate limit, and paraphrasing it would lose
    // the distinction the person needs.
    throw new Error(payload.message ?? `Could not complete that step (${response.status}).`)
  }

  return response
}

function done() {
  router.visit('/', { replace: true })
}
</script>

<template>
  <main class="mx-auto max-w-xl p-8">
    <h1 class="text-2xl font-semibold">Set up two-factor authentication</h1>

    <p v-if="required" class="mt-3 rounded bg-amber-50 p-4 text-sm text-amber-900">
      <!-- SPEC 8.13.4: "required above `project_writer`" — so the reason is
           knowable, and printing it saves one support conversation per person. -->
      Your account holds a role that requires it:
      <strong>{{ because.join(', ') || 'an administrative role' }}</strong>.
      <template v-if="installationWide">
        Two-factor authentication is required across this installation.
      </template>
      <template v-else>
        It is required by an organisation you are a member of.
      </template>
      You will not be able to use the dashboard until this is finished.
    </p>

    <p v-else class="mt-3 text-sm text-gray-600">
      Two-factor authentication is not required for your account. Setting it up anyway is a
      good idea.
    </p>

    <p
      v-if="enrolled"
      class="mt-6 rounded bg-green-50 p-4 text-sm text-green-900"
      data-testid="already-enrolled"
    >
      Two-factor authentication is already set up on this account.
    </p>

    <section v-if="!enrolled" class="mt-8">
      <button
        v-if="!qr"
        type="button"
        class="rounded bg-gray-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
        :disabled="working"
        data-testid="begin"
        @click="begin"
      >
        Start
      </button>

      <div v-else-if="!recovery.length">
        <p class="text-sm text-gray-600">
          Scan this with an authenticator app, then enter the six-digit code it shows.
        </p>

        <!-- Fortify renders the SVG server-side; it carries no script. -->
        <div class="mt-4 inline-block rounded border border-gray-200 p-4" v-html="qr" />

        <p class="mt-3 text-xs text-gray-500">
          Cannot scan it? Enter this key by hand:
          <code class="font-mono">{{ secret }}</code>
        </p>

        <form class="mt-6 flex items-end gap-3" @submit.prevent="confirm">
          <label class="block text-sm">
            <span class="text-gray-500">Code from your app</span>
            <input
              v-model="code"
              class="mt-1 w-32 rounded border-gray-300 font-mono text-sm"
              inputmode="numeric"
              autocomplete="one-time-code"
              name="code"
            />
          </label>

          <button
            type="submit"
            class="rounded bg-gray-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
            :disabled="working || !code"
            data-testid="confirm"
          >
            Confirm
          </button>
        </form>
      </div>

      <div v-else data-testid="recovery-codes">
        <p class="rounded bg-green-50 p-4 text-sm text-green-900">
          Two-factor authentication is on.
        </p>

        <!-- 🛑 Shown once, and said to be shown once. A person who closes this
             without saving them has one route back in: an operator clearing
             the columns. -->
        <p class="mt-6 text-sm text-gray-600">
          Save these recovery codes somewhere safe. Each one works once, and this is the only
          time they are shown.
        </p>

        <ul class="mt-3 grid grid-cols-2 gap-1 rounded bg-gray-50 p-4 font-mono text-xs">
          <li v-for="entry in recovery" :key="entry">{{ entry }}</li>
        </ul>

        <button
          type="button"
          class="mt-6 rounded bg-gray-900 px-4 py-2 text-sm font-medium text-white"
          data-testid="done"
          @click="done"
        >
          Continue to the dashboard
        </button>
      </div>
    </section>

    <p v-if="error" class="mt-6 rounded bg-red-50 p-4 text-sm text-red-900" data-testid="error">
      {{ error }}
    </p>
  </main>
</template>
