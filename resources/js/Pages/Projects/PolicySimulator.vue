<script setup>
// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0
import { computed, reactive } from 'vue'
import { router } from '@inertiajs/vue3'

const props = defineProps({
  organisation: { type: Object, required: true },
  project: { type: Object, required: true },

  // The hosts this project is served on and the identities that exist, both
  // from the server. 🛑 SPEC 8.9.3 resolves a project from the host and path,
  // so a typo gives an answer about another project — offering the real list
  // is what stops the likeliest operator error from reading as a policy bug.
  hosts: { type: Array, default: () => [] },
  identities: { type: Array, default: () => [] },
  members: { type: Array, default: () => [] },

  // What was asked, echoed back so a linked answer reopens its own question.
  asked: { type: Object, required: true },

  // 🛑 SPEC 8.12.25's sentence, decided entirely server-side. This template
  // renders it and computes nothing about access: App\Access\PolicySimulator
  // is a renderer of EffectiveAccess's answer, and a page that derived
  // "allowed" from a status code would be a third opinion.
  answer: { type: Object, default: null },

  // Why the simulator could not be asked — an identity that is absent from
  // this tenant or has been deprovisioned. Not a denial.
  refused: { type: String, default: null },
})

const form = reactive({
  host: props.asked.host ?? props.hosts[0]?.host ?? '',
  path: props.asked.path ?? '/',
  identity: props.asked.identity ?? 'anonymous',
  subject: props.asked.subject ?? '',
  address: props.asked.address ?? '',
  surface: props.asked.surface ?? 'proxy',
})

const subjects = computed(() =>
  form.identity === 'reader' ? props.identities : form.identity === 'member' ? props.members : [],
)

const verdict = computed(() => {
  if (props.answer === null) return null
  if (!props.answer.resolved) return 'unresolved'
  if (props.answer.decision.allowed) return 'allow'
  return props.answer.decision.challenge ? 'challenge' : 'deny'
})

// A GET, so the answer is linkable: see the route's own note. `replace` keeps
// one history entry per question rather than one per keystroke of refinement.
function ask() {
  router.get(
    `/o/${props.organisation.slug}/projects/${props.project.slug}/policy/simulate`,
    {
      host: form.host,
      path: form.path,
      identity: form.identity,
      subject: form.identity === 'anonymous' ? '' : form.subject,
      address: form.address,
      surface: form.surface,
    },
    { replace: true, preserveScroll: true },
  )
}
</script>

<template>
  <main class="mx-auto max-w-3xl p-8">
    <h1 class="text-2xl font-semibold">Policy simulator</h1>
    <p class="mt-2 text-sm text-gray-600">
      As one identity, on one URL: what the reader would get, which rule decided it, and which
      binding satisfied it. Nothing is served and nothing is recorded against the reader — this
      asks the same decision a real request asks.
    </p>

    <form class="mt-8 space-y-4" data-testid="simulator-form" @submit.prevent="ask">
      <div class="grid grid-cols-3 gap-4">
        <label class="col-span-1 block text-sm">
          <span class="text-gray-500">Host</span>
          <select v-model="form.host" class="mt-1 w-full rounded border-gray-300 text-sm" name="host">
            <option v-for="host in hosts" :key="host.host" :value="host.host">
              {{ host.host }}{{ host.state === 'verified' ? '' : ` (${host.state})` }}
            </option>
          </select>
        </label>

        <label class="col-span-2 block text-sm">
          <span class="text-gray-500">Path</span>
          <input
            v-model="form.path"
            class="mt-1 w-full rounded border-gray-300 font-mono text-sm"
            name="path"
            placeholder="/en/latest/guide/internal.html"
          />
        </label>
      </div>

      <div class="grid grid-cols-3 gap-4">
        <label class="block text-sm">
          <span class="text-gray-500">Identity</span>
          <select
            v-model="form.identity"
            class="mt-1 w-full rounded border-gray-300 text-sm"
            name="identity"
          >
            <!-- 🛑 Anonymous first and selected by default: SPEC 19/40's
                 observed failure mode is a project that is public without
                 anybody meaning it, and this is the question that catches it. -->
            <option value="anonymous">Anonymous (nobody)</option>
            <option value="reader">A documentation reader</option>
            <option value="member">A dashboard member</option>
          </select>
        </label>

        <label v-if="form.identity !== 'anonymous'" class="block text-sm">
          <span class="text-gray-500">Who</span>
          <select
            v-model="form.subject"
            class="mt-1 w-full rounded border-gray-300 text-sm"
            name="subject"
          >
            <option value="">Choose…</option>
            <option v-for="subject in subjects" :key="subject.uuid" :value="subject.uuid">
              {{ subject.label }}
            </option>
          </select>
        </label>

        <label class="block text-sm">
          <!-- 🛑 Beside the identity, not inside it. SPEC 8.12.17 classifies
               `ip_allowlist` as a {gate} and never an identity: being on a
               network does not make somebody anybody. -->
          <span class="text-gray-500">From address (optional)</span>
          <input
            v-model="form.address"
            class="mt-1 w-full rounded border-gray-300 font-mono text-sm"
            name="address"
            placeholder="198.51.100.4"
          />
        </label>
      </div>

      <div class="flex items-end gap-4">
        <label class="block text-sm">
          <span class="text-gray-500">Surface</span>
          <select
            v-model="form.surface"
            class="mt-1 rounded border-gray-300 text-sm"
            name="surface"
          >
            <!-- SPEC 8.12.21's four. `search` legitimately answers differently
                 while a project's search generation lags its policy. -->
            <option value="proxy">proxy</option>
            <option value="download">download</option>
            <option value="search">search</option>
            <option value="addons">addons</option>
          </select>
        </label>

        <button
          type="submit"
          class="rounded bg-gray-900 px-4 py-2 text-sm font-medium text-white"
          data-testid="simulate"
        >
          Simulate
        </button>
      </div>
    </form>

    <p
      v-if="refused"
      class="mt-8 rounded bg-amber-50 p-4 text-sm text-amber-900"
      data-testid="refused"
    >
      <!-- 🛑 Not a denial. The simulator could not be asked, which is a
           statement about the identity and not about the policy. -->
      {{
        refused === 'identity_deprovisioned'
          ? 'That identity has been deprovisioned, so there is no reader to simulate.'
          : 'No such identity on this organisation.'
      }}
    </p>

    <section v-if="answer" class="mt-8" data-testid="answer">
      <div
        class="rounded p-4"
        :class="{
          'bg-green-50 text-green-900': verdict === 'allow',
          'bg-red-50 text-red-900': verdict === 'deny',
          'bg-amber-50 text-amber-900': verdict === 'challenge',
          'bg-gray-100 text-gray-700': verdict === 'unresolved',
        }"
      >
        <p class="text-lg font-semibold" data-testid="verdict">
          <template v-if="verdict === 'unresolved'">
            This URL resolves to nothing to authorise
          </template>
          <template v-else-if="verdict === 'allow'">Allowed</template>
          <template v-else-if="verdict === 'challenge'">
            Challenged — {{ answer.decision.status }}
          </template>
          <template v-else>Denied — {{ answer.decision.status }}</template>
        </p>

        <!-- The decision header's own vocabulary, so this page and a reader's
             own response say the same thing in the same words. -->
        <code class="mt-1 block text-xs" data-testid="summary">{{ answer.summary }}</code>
      </div>

      <dl v-if="answer.resolved" class="mt-6 grid grid-cols-3 gap-2 text-sm">
        <dt class="text-gray-500">Rule</dt>
        <dd class="col-span-2" data-testid="rule">
          <template v-if="answer.decision.rule">
            rule {{ answer.decision.rule.position }} — {{ answer.decision.rule.label }}
            ({{ answer.decision.rule.allow ? 'allow' : 'deny' }})
          </template>
          <template v-else>
            <!-- SPEC 12.3's lattice can decide without a rule: see
                 ReaderContext::strongestLeaf(). -->
            no rule matched; decided by the visibility lattice
          </template>
        </dd>

        <dt class="text-gray-500">Satisfied by</dt>
        <dd class="col-span-2" data-testid="satisfied-by">
          <template v-if="answer.decision.satisfied_by">
            {{ answer.decision.satisfied_by
            }}<template v-if="answer.decision.satisfied_by_binding">
              — binding “{{ answer.decision.satisfied_by_binding }}”</template
            >
          </template>
          <template v-else>nothing</template>
        </dd>

        <dt class="text-gray-500">Reason</dt>
        <dd class="col-span-2"><code class="text-xs">{{ answer.decision.reason }}</code></dd>

        <dt class="text-gray-500">Level</dt>
        <dd class="col-span-2">
          required {{ answer.decision.required }}, established
          {{ answer.decision.established }}
        </dd>

        <dt class="text-gray-500">Resolved to</dt>
        <dd class="col-span-2">
          {{ answer.project_slug }} · {{ answer.language }}/{{ answer.version_slug }}
        </dd>

        <!-- 🛑 The space SPEC 12.3's `path_patterns` are written in. An
             operator is at least as likely to have the wrong path space as
             the wrong rule. -->
        <dt class="text-gray-500">Policy saw path</dt>
        <dd class="col-span-2">
          <code class="text-xs">{{ answer.mount_relative_path || '(mount root)' }}</code>
        </dd>

        <dt class="text-gray-500">Routed by</dt>
        <dd class="col-span-2"><code class="text-xs">{{ answer.route_rule }}</code></dd>

        <template v-if="answer.identity_label">
          <dt class="text-gray-500">Identity</dt>
          <dd class="col-span-2">
            {{ answer.identity_label
            }}<template v-if="answer.identity_groups.length">
              — groups: {{ answer.identity_groups.join(', ') }}</template
            >
          </dd>
        </template>

        <dt class="text-gray-500">Publicly cacheable</dt>
        <dd class="col-span-2">{{ answer.decision.publicly_cacheable ? 'yes' : 'no' }}</dd>
      </dl>

      <dl v-else class="mt-6 grid grid-cols-3 gap-2 text-sm">
        <dt class="text-gray-500">Routed by</dt>
        <dd class="col-span-2"><code class="text-xs">{{ answer.route_rule }}</code></dd>

        <template v-if="answer.redirect_to">
          <dt class="text-gray-500">Redirects to</dt>
          <!-- 🛑 Reported, not followed: following it would answer about a
               different URL and label the answer with this one. -->
          <dd class="col-span-2"><code class="text-xs">{{ answer.redirect_to }}</code></dd>
        </template>

        <template v-if="answer.rejection">
          <dt class="text-gray-500">Because</dt>
          <dd class="col-span-2"><code class="text-xs">{{ answer.rejection }}</code></dd>
        </template>
      </dl>

      <!--
        🛑 SPEC 8.12.25 is only useful if the operator can tell two denials
        apart: "your policy refuses this identity" and "this identity was never
        the one that rule is for". SPEC 9.1.4 stores a share link's and a reader
        token's secret hashed, so no simulation can establish those leaves —
        and saying so is the honest answer, not hand-building the leaf.
      -->
      <p
        v-if="answer.unsimulatable.length"
        class="mt-6 rounded bg-amber-50 p-4 text-sm text-amber-900"
        data-testid="unsimulatable"
      >
        A rule matching this URL depends on
        <strong>{{ answer.unsimulatable.join(', ') }}</strong>, which no simulation can establish:
        those credentials are stored hashed, so there is nothing to present. A reader holding one
        may get a different answer.
      </p>

      <!-- A shadow rule is the next edit's behaviour, visible before the edit —
           which is the same reachability SPEC 8.12.22's nightly linter watches. -->
      <p
        v-if="answer.resolved && answer.decision.shadow_rule"
        class="mt-4 rounded bg-blue-50 p-4 text-sm text-blue-900"
        data-testid="shadow-rule"
      >
        Shadow rule {{ answer.decision.shadow_rule.position }} —
        {{ answer.decision.shadow_rule.label }} would have matched
        ({{ answer.decision.shadow_rule.allow ? 'allow' : 'deny' }}). It is recorded and not
        enforced.
      </p>
    </section>
  </main>
</template>
