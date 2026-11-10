<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

use Illuminate\Support\Facades\DB;

/**
 * 🛑 The two numbers §8.12.21's gate compares, read live.
 *
 * > §8.12.21: "a project's search MUST be **disabled** while its search
 * > generation lags its policy generation".
 *
 * ## 🛑 Why these are read from the row and not from the routing snapshot
 *
 * `App\Serving\SnapshotProject` already carries `policyGeneration`, and putting
 * `search_policy_generation` beside it would look like the obvious
 * optimisation. It would be a **defect**, and the reason is worth stating
 * because the next person to look at §9.2's budgets will think of it again.
 *
 * The routing snapshot is keyed, when it is cached at all, on `routing_epoch`
 * (§8.9.10) — and §10.8 gives that epoch "domain, mount, redirect, version
 * pointer change". **Indexing bumps none of them.** So a cached snapshot would
 * carry the `search_policy_generation` from before the reindex, and a project
 * whose index had just caught up would keep failing the gate until something
 * unrelated moved its routing epoch. Fail-closed, permanently, and looking
 * exactly like a design decision rather than a bug.
 *
 * So the value is read from `projects` on the search path. It is one indexed
 * read against §9.2's 200 ms search budget, on a path that is about to run a
 * `MATCH … AGAINST` measured at 80 ms.
 *
 * ## The honest note about freshness
 *
 * `policy_generation` is read here too, from the same row and the same
 * statement, so the comparison is between two values read at one instant. The
 * routing snapshot is loaded per request today and is therefore live as well —
 * but reading both halves here means the gate stays exact even if a later phase
 * caches the snapshot, instead of silently becoming "as fresh as whatever that
 * phase chose".
 */
final readonly class SearchGenerations
{
    /**
     * @param  int  $searchGeneration  §10.8's epoch: which `search_mount_scopes`
     *                                 generation is live. Zero means never
     *                                 indexed.
     * @param  int  $searchPolicyGeneration  the `policy_generation` the live
     *                                       generation was built under
     * @param  int  $policyGeneration  the project's current policy generation
     */
    public function __construct(
        public int $searchGeneration,
        public int $searchPolicyGeneration,
        public int $policyGeneration,
    ) {}

    /**
     * One read, for one project.
     *
     * @param  string  $projectId  raw 16 bytes
     */
    public static function forProject(string $projectId): self
    {
        $row = DB::table('projects')
            ->where('id', $projectId)
            ->first(['search_generation', 'search_policy_generation', 'policy_generation']);

        if ($row === null) {
            /*
             * 🛑 A project that is not there fails closed: generation 0, which
             * {@see self::isIndexed()} reads as "never indexed" and which makes
             * the scope empty. The caller holds a routing snapshot naming this
             * project, so the row being absent means it was deleted between the
             * snapshot load and now — and a deleted project's search index is
             * the last thing that should still answer.
             */
            return new self(0, 0, 0);
        }

        return new self(
            searchGeneration: (int) $row->search_generation,
            searchPolicyGeneration: (int) $row->search_policy_generation,
            policyGeneration: (int) $row->policy_generation,
        );
    }

    /** Whether a live generation exists at all. */
    public function isIndexed(): bool
    {
        return $this->searchGeneration > 0;
    }

    /**
     * 🛑 §8.12.21's comparison: does the index lag the policy?
     *
     * `<` and not `!=`. A `search_policy_generation` **above** the current
     * `policy_generation` cannot happen through any code path — the indexer
     * records a value it read from the same column — but if it did, the index
     * would be ahead of the policy rather than behind it, which is not the
     * failure this gate exists for. Treating it as stale would disable search
     * over an impossible condition; treating it as current is the reading that
     * matches what the requirement says.
     */
    public function lagsPolicy(): bool
    {
        return $this->searchPolicyGeneration < $this->policyGeneration;
    }
}
