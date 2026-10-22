<script setup>
// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0
defineProps({
  project: { type: Object, required: true },
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
  </main>
</template>
