<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers;

use App\Serving\SnapshotProject;

/**
 * Run every binding in scope against what a reader presented.
 *
 * 🛑 **Every binding, not the first that satisfies.** The temptation is to stop
 * at the first success, and it is wrong twice over:
 *
 * 1. §12.3 lets a rule name a **specific** binding, so a reader who satisfies
 *    two needs both recorded — stopping early would make a rule naming the
 *    second binding fail for a reader who holds both credentials.
 * 2. §8.12.19's degraded check has to see every binding. A short-circuit on the
 *    first success would skip a degraded one and serve the reader, which is the
 *    "fall back to another provider" the requirement forbids.
 *
 * The cost is bounded: §8.12.3 resolves **one binding per driver type**, so the
 * loop is at most the number of registered drivers — six in v1 — and in
 * practice one or two.
 *
 * 🛑 **A driver that throws is a degraded binding, not a 500.** §8.12.19 has an
 * answer for a provider that cannot currently work and it is a branded 503; an
 * uncaught exception from one driver would take out every page of a project
 * with no explanation, including the pages that other bindings would have
 * served.
 */
final readonly class ProviderResolver
{
    public function __construct(private Bindings $bindings) {}

    /**
     * @param  SnapshotProject  $project  the resolved project; its `authzEpoch`
     *                                    keys the binding cache, so a binding
     *                                    edit takes effect on the next request
     */
    public function resolve(SnapshotProject $project, ReaderPresentation $presented): ProviderOutcome
    {
        $contexts = $this->bindings->contextsFor(
            $project->id,
            $project->organisationId,
            $project->authzEpoch,
        );

        if ($contexts === []) {
            /*
             * 🛑 No bindings is **not** the same as no access, and it is not
             * this class's business which. §12.3's lattice decides: a public
             * project with no bindings serves, and a `members` project with
             * none denies — because the reader reaches no identity leaf, not
             * because this returned something special.
             */
            return ProviderOutcome::none();
        }

        $attempts = [];

        foreach ($contexts as $binding) {
            /*
             * 🛑 §8.12.19's `degraded` is checked **before** the driver runs,
             * so a degraded binding's driver is never asked. Asking it and
             * discarding the answer would mean a degraded `password` binding
             * still consumed a rate-limit slot and still ran Argon2.
             */
            if ($binding->state->deniesWithServiceUnavailable()) {
                $attempts[] = ['binding' => $binding, 'result' => AttemptResult::degraded()];

                continue;
            }

            /*
             * 🛑 §8.12.19: only `active` authenticates. `draft`, `verifying`
             * and `disabled` contribute nothing — not a rejection, because the
             * reader did not present anything to that binding; it simply is not
             * in service.
             */
            if (! $binding->isUsable()) {
                continue;
            }

            $driver = DriverRegistry::for($binding->type);

            if ($driver === null) {
                /*
                 * A stored type with no registered driver — a third-party
                 * driver that was uninstalled, or a row from a future version.
                 *
                 * 🛑 **Degraded, not skipped.** Skipping would silently remove a
                 * guard the operator configured: a project whose only binding
                 * was an uninstalled driver would fall back to whatever the
                 * lattice alone says, which for a public project is public.
                 * §8.12.19's 503 is the honest answer, and it names the binding
                 * so the operator can see which.
                 */
                $attempts[] = ['binding' => $binding, 'result' => AttemptResult::degraded()];

                continue;
            }

            try {
                $attempts[] = ['binding' => $binding, 'result' => $driver->attempt($binding, $presented)];
            } catch (\Throwable) {
                /* See the class note: a throwing driver is a degraded binding. */
                $attempts[] = ['binding' => $binding, 'result' => AttemptResult::degraded()];
            }
        }

        return ProviderOutcome::merge($attempts, $presented->carriesCredential());
    }
}
