<script setup>
// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0
import { computed } from 'vue'

const props = defineProps({
  project: { type: Object, required: true },

  // 🛑 SPEC 8.16.2's limits, READ FROM THE RUNNING SERVER by
  // App\Search\EngineLimits — not restated here. `innodb_ft_min_token_size` is
  // a server variable, so a page printing the specification's 3 while the
  // server said 4 would be wrong about the one number the reader came to check.
  limits: { type: Object, required: true },

  // SPEC 8.16.12's published capability matrix, generated from the drivers.
  capabilities: { type: Array, default: () => [] },

  engine: { type: Object, required: true },

  // 🛑 SPEC 8.12.21's state. "Search is disabled while the index lags the
  // policy" persists until a reindex runs and looks like an empty corpus from
  // every other angle, so it is said in words here.
  generations: { type: Object, required: true },

  versions: { type: Array, default: () => [] },
  ranking: { type: Object, required: true },
})

// 🛑 Nothing on this page computes a limit, a capability or a verdict. Every
// value is the server's answer rendered: the engine reports its own limits
// (SPEC 8.16.2), the driver reports its own capabilities (SPEC 8.16.12), and
// App\Search\SearchGenerations reports whether search is disabled. A page that
// derived "disabled" from two numbers would be a second opinion about a
// fail-closed security gate.
const indexState = computed(() => {
  if (props.generations.disabled_because_stale) return 'disabled'
  if (!props.generations.indexed) return 'never-indexed'
  return 'live'
})

const unsupported = computed(() => props.capabilities.filter((row) => !row.supported))
const supported = computed(() => props.capabilities.filter((row) => row.supported))
</script>

<template>
  <main class="mx-auto max-w-3xl p-8">
    <h1 class="text-2xl font-semibold">Search</h1>
    <p class="mt-2 text-sm text-gray-600">
      How search behaves for <strong>{{ project.name }}</strong>, and what this engine can and
      cannot find. Indexing runs hourly; it is not a setting on this page.
    </p>

    <!-- ──────────────────────────────────────────── SPEC 8.12.21's state -->
    <section class="mt-8" data-testid="search-state">
      <h2 class="text-lg font-medium">State</h2>

      <p
        v-if="indexState === 'disabled'"
        class="mt-2 rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900"
        data-testid="search-disabled"
      >
        <strong>Search is disabled for this project.</strong>
        Its index was built under policy generation
        {{ generations.built_under_policy_generation }} and the policy is now at
        {{ generations.policy_generation }} — so the index no longer reflects who may read what.
        It is disabled rather than served stale, because stale results would be documents the new
        policy refuses. The next indexing pass re-enables it; nothing has been discarded.
      </p>

      <p
        v-else-if="indexState === 'never-indexed'"
        class="mt-2 rounded border border-gray-300 bg-gray-50 p-3 text-sm text-gray-700"
        data-testid="search-never-indexed"
      >
        This project has not been indexed yet. Search returns nothing until the next pass.
      </p>

      <p v-else class="mt-2 text-sm text-gray-700" data-testid="search-live">
        Indexed
        <time v-if="generations.indexed_at" :datetime="generations.indexed_at">
          {{ generations.indexed_at }}
        </time>
        <span v-else>at an unrecorded time</span>
        — {{ generations.section_count.toLocaleString() }} sections, generation
        {{ generations.search_generation }}.
      </p>
    </section>

    <!-- ───────────────────────────────── SPEC 8.16.2, the whole point -->
    <section class="mt-8" data-testid="search-limits">
      <h2 class="text-lg font-medium">What this engine cannot find</h2>
      <p class="mt-2 text-sm text-gray-600">
        <strong>{{ limits.driver_label }}</strong
        >. These are real limits, not advice — a term below the minimum length is not in the index
        at all, so no amount of rephrasing finds it.
      </p>

      <dl class="mt-4 grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
        <dt class="text-gray-500">Shortest indexed word</dt>
        <dd data-testid="min-token-size">
          {{ limits.min_token_size }} character{{ limits.min_token_size === 1 ? '' : 's' }}
        </dd>

        <dt class="text-gray-500">Stopwords</dt>
        <dd data-testid="stopword-count">
          {{ limits.stopword_count }}
          <span v-if="limits.stopword_table" class="text-gray-500">
            (from {{ limits.stopword_table }})
          </span>
        </dd>

        <dt class="text-gray-500">Stemming</dt>
        <dd>{{ limits.stemming ? 'yes' : 'no' }}</dd>

        <dt class="text-gray-500">Typo tolerance</dt>
        <dd>{{ limits.typo_tolerance ? 'yes' : 'no' }}</dd>
      </dl>

      <!-- 🛑 SPEC 8.16.2: "The illustration must use a TWO-character term."
           `go` is first because three characters clears the default minimum, so
           every example a well-meaning author reaches for (api, ssl, jwt) works
           and the surprise is never met until a reader reports it. ADR 0004
           calls "Why can't I find go?" the real first support question. -->
      <table class="mt-6 w-full text-left text-sm" data-testid="search-illustrations">
        <caption class="sr-only">
          Example searches and what they return on this engine
        </caption>
        <thead>
          <tr class="border-b text-gray-500">
            <th scope="col" class="py-1 pr-4 font-medium">Searching for</th>
            <th scope="col" class="py-1 pr-4 font-medium">Returns</th>
            <th scope="col" class="py-1 font-medium">Why</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in limits.illustrations"
            :key="row.term"
            class="border-b border-gray-100 align-top"
          >
            <th scope="row" class="py-2 pr-4 font-mono font-normal">{{ row.term }}</th>
            <td class="py-2 pr-4">{{ row.outcome }}</td>
            <td class="py-2 text-gray-600">
              {{ row.why }}
              <!-- 🛑 A measurement is labelled as one. ADR 0004's figure was
                   measured at 200,000 sections and no page render can repeat
                   it; presenting it as a live reading would over-claim a
                   precision this page does not have. -->
              <span v-if="!row.live" class="text-gray-400">(measured, not read from this server)</span>
            </td>
          </tr>
        </tbody>
      </table>
    </section>

    <!-- ──────────────────────────── SPEC 8.16.12's capability matrix -->
    <section class="mt-8" data-testid="search-capabilities">
      <h2 class="text-lg font-medium">Query syntax</h2>
      <p class="mt-2 text-sm text-gray-600">
        Terms are combined with AND. A phrase in double quotes is matched exactly. Everything else
        — <code>OR</code>, <code>~</code>, <code>*</code>, a leading <code>-</code> — is searched
        for as ordinary text rather than treated as an operator, so a query never fails with an
        error.
      </p>

      <ul class="mt-4 space-y-1 text-sm">
        <li v-for="row in supported" :key="row.capability" class="text-gray-700">
          <span aria-hidden="true">✓</span>
          <span class="sr-only">Supported:</span>
          {{ row.label }}
        </li>
      </ul>

      <ul class="mt-4 space-y-2 text-sm" data-testid="search-unsupported">
        <li v-for="row in unsupported" :key="row.capability" class="text-gray-600">
          <span aria-hidden="true">✗</span>
          <span class="sr-only">Not supported:</span>
          <strong class="font-medium">{{ row.label }}</strong>
          <span v-if="row.note"> — {{ row.note }}</span>
        </li>
      </ul>
    </section>

    <!-- ─────────────────────────────────── SPEC 8.16.9's three channels -->
    <section class="mt-8" data-testid="search-versions">
      <h2 class="text-lg font-medium">What is indexed</h2>
      <p class="mt-2 text-sm text-gray-600">
        The <code>default</code>, <code>stable</code> and <code>latest</code> versions only.
        Hidden and inactive versions are excluded, so a version a maintainer unlisted does not
        appear in its own search results.
      </p>

      <table class="mt-4 w-full text-left text-sm">
        <thead>
          <tr class="border-b text-gray-500">
            <th scope="col" class="py-1 pr-4 font-medium">Channel</th>
            <th scope="col" class="py-1 pr-4 font-medium">Version</th>
            <th scope="col" class="py-1 pr-4 font-medium">Extracted from</th>
            <th scope="col" class="py-1 pr-4 font-medium">Sections</th>
            <th scope="col" class="py-1 font-medium">Pages skipped</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in versions" :key="row.channel" class="border-b border-gray-100">
            <th scope="row" class="py-2 pr-4 font-mono font-normal">{{ row.channel }}</th>
            <td class="py-2 pr-4">
              {{ row.slug ?? '—' }}
              <span v-if="row.slug && !row.indexed" class="text-amber-700">
                (not indexed: hidden, inactive or unpublished)
              </span>
            </td>
            <td class="py-2 pr-4">{{ row.report?.extracted_from ?? '—' }}</td>
            <td class="py-2 pr-4">{{ row.report?.sections ?? '—' }}</td>
            <!-- A skipped page is a page that is not findable, so it is a
                 number an operator needs rather than a detail. -->
            <td class="py-2">{{ row.report?.skipped ?? '—' }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <!-- ────────────────────────────────────── SPEC 8.16.3's ranking -->
    <section class="mt-8" data-testid="search-ranking">
      <h2 class="text-lg font-medium">Ranking and exclusions</h2>
      <p class="mt-2 text-sm text-gray-600">
        From <code>search.ranking</code> and <code>search.ignore</code> in this project's
        configuration file.
        <span v-if="!ranking.declared">
          This project declares none, so these are the defaults a
          <code>.readthedocs.yaml</code> would have.
        </span>
      </p>

      <ul v-if="ranking.ranking.length" class="mt-3 space-y-1 font-mono text-sm">
        <li v-for="row in ranking.ranking" :key="row.pattern">
          {{ row.pattern }} → {{ row.rank > 0 ? '+' : '' }}{{ row.rank }}
        </li>
      </ul>
      <p v-else class="mt-3 text-sm text-gray-500">No page ranking is declared.</p>

      <p class="mt-4 text-sm text-gray-500">Never indexed:</p>
      <ul class="mt-1 space-y-1 font-mono text-sm">
        <li v-for="pattern in ranking.ignore" :key="pattern">{{ pattern }}</li>
      </ul>
    </section>

    <!-- ───────────────────────────────── SPEC 8.16.1's threshold -->
    <section class="mt-8" data-testid="search-engine">
      <h2 class="text-lg font-medium">Engine</h2>

      <p class="mt-2 text-sm text-gray-700">
        {{ engine.label }} —
        <span v-if="engine.needs_a_service">an additional service</span>
        <span v-else>no additional service required</span>.
        <span v-if="!engine.reachable" class="text-red-700" data-testid="engine-unreachable">
          It is not answering, so search returns nothing until it does.
        </span>
      </p>

      <p
        v-if="engine.above_threshold"
        class="mt-3 rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900"
        data-testid="engine-threshold"
      >
        This installation holds about {{ engine.sections.toLocaleString() }} sections, above the
        {{ engine.threshold.toLocaleString() }} at which Meilisearch is recommended. The default
        engine's filtered query was measured at 80 ms against 10 ms unfiltered at that size, and
        the cost grows with how many sections match rather than with how many results are asked
        for — so a smaller result limit does not make a broad query cheap.
      </p>
    </section>
  </main>
</template>
