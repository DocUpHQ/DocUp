<script setup>
// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0
//
// Deliberately plain. Phase 02's exit criteria are about tenancy and the audit
// chain; branding is a closed token registry in Phase 15 (SPEC 8.14), and
// anything invented here would have to be unpicked then.
defineProps({
  organisation: { type: Object, required: true },
  projects: { type: Array, required: true },
})
</script>

<template>
  <main class="mx-auto max-w-3xl p-8">
    <h1 class="text-2xl font-semibold">{{ organisation.name }}</h1>

    <ul v-if="projects.length" class="mt-6 divide-y">
      <li v-for="project in projects" :key="project.uuid" class="py-3">
        <a :href="`/o/${organisation.slug}/projects/${project.slug}`" class="font-medium underline">
          {{ project.name }}
        </a>
        <span class="ml-2 text-sm text-gray-500">{{ project.visibility }}</span>
      </li>
    </ul>

    <p v-else class="mt-6 text-gray-500">No projects yet.</p>
  </main>
</template>
