<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Admission;

/**
 * §8.5.5's two admission profiles.
 *
 * > "Admission MUST offer two profiles: `simple` (concurrency is the worker
 * > count; per-project non-overlapping with a queued cap and coalescing) and
 * > `fair` (leader-locked dispatcher, nested installation/organisation/project
 * > semaphores, deficit round-robin weighted by organisation share). 🛑 Read
 * > the Docs holds an **organisation-scoped** lock over a **per-project**
 * > FIFO queue — a verified fairness bug where one organisation's backlog
 * > starves another's first build. Neither profile may reproduce it."
 *
 * 🛑 **`simple` is not "fair, without the fairness".** It is strict FIFO over
 * the whole installation, which cannot starve anybody either: the order is
 * arrival order and one organisation's fiftieth build is behind another's
 * first by construction. What it lacks is a *share* — a busy organisation
 * takes a proportional amount of a busy installation rather than a weighted
 * one. The starvation bug §8.5.5 names comes from queueing **per project**
 * under a lock held **per organisation**, and neither profile does that.
 */
enum AdmissionProfile: string
{
    /** Installation-wide FIFO under the slot ceilings. The default. */
    case Simple = 'simple';

    /** Deficit round-robin between organisations, weighted by share. */
    case Fair = 'fair';

    /**
     * Unknown values become `simple`.
     *
     * The safe fallback here is the *simpler* profile rather than the
     * cleverer one: a typo in `DOCUP_ADMISSION` should not silently enable
     * a dispatcher whose behaviour the operator has not read about.
     */
    public static function fromConfig(mixed $value): self
    {
        return is_string($value) ? (self::tryFrom($value) ?? self::Simple) : self::Simple;
    }
}
