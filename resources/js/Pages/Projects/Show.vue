<script setup>
// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0
defineProps({
  project: { type: Object, required: true },

  // SPEC 8.7.11's composition rows. Each carries `reuse_warning` already
  // decided by App\Composition\CompositionSummary — this template renders
  // it and never recomputes it, so there is one place that knows what
  // `injected` costs.
  composition: { type: Array, default: () => [] },
})
</script>

<template>
  <main class="mx-auto max-w-3xl p-8">
    <h1 class="text-2xl font-semibold">{{ project.name }}</h1>
    <p v-if="project.description" class="mt-2 text-gray-600">{{ project.description }}</p>

    <dl class="mt-6 grid grid-cols-2 gap-2 text-sm">
      <dt class="text-gray-500">Visibility</dt>
      <dd>{{ project.visibility }}</dd>
      <dt class="text-gray-500">Inherits organisation roles</dt>
      <dd>{{ project.inherits_organisation_roles ? 'yes' : 'no' }}</dd>
    </dl>

    <section v-if="composition.length" class="mt-10">
      <h2 class="text-lg font-semibold">Composition</h2>

      <ul class="mt-4 space-y-4">
        <li
          v-for="mount in composition"
          :key="`${mount.version}-${mount.component}`"
          class="rounded border border-gray-200 p-4 text-sm"
        >
          <div class="flex items-baseline justify-between gap-4">
            <span class="font-medium">{{ mount.component_name }}</span>
            <code class="text-xs text-gray-500">{{ mount.component }}</code>
          </div>

          <dl class="mt-3 grid grid-cols-2 gap-1 text-xs">
            <dt class="text-gray-500">Version</dt>
            <dd>{{ mount.language }}/{{ mount.version }}</dd>

            <dt class="text-gray-500">Mounted at</dt>
            <dd>{{ mount.mount_path === '' ? '/ (primary)' : `/${mount.mount_path}` }}</dd>

            <dt class="text-gray-500">Source</dt>
            <dd>{{ mount.source_path === '' ? 'repository root' : mount.source_path }}</dd>

            <!-- SPEC 8.7.7's ceiling, visible beside the mount it governs. -->
            <dt class="text-gray-500">Minimum access</dt>
            <dd>{{ mount.min_access }}</dd>

            <dt class="text-gray-500">Base URL mode</dt>
            <dd>{{ mount.base_url_mode }}</dd>
          </dl>

          <!--
            🛑 SPEC 8.7.11's required warning. Rendered from the server's
            own `reuse_warning`, so the condition and the wording live in
            one place and a layout tidy-up cannot quietly delete the rule.
          -->
          <p
            v-if="mount.reuse_warning"
            class="mt-3 rounded bg-amber-50 p-3 text-xs text-amber-900"
            data-testid="reuse-warning"
          >
            {{ mount.reuse_warning }}
          </p>
        </li>
      </ul>
    </section>
  </main>
</template>
