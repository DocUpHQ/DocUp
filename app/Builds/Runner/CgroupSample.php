<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Runner;

/**
 * One reading of a build container's resource counters (§8.5.15, §8.5.18).
 *
 * Counters, not booleans, because `oom_kill 1` and `oom_kill 40` are
 * different stories about the same build and the author needs the second
 * one to understand what their generator did.
 */
final readonly class CgroupSample
{
    public function __construct(
        /** `memory.events:oom_kill` (v2) or `memory.oom_control`'s `oom_kill` (v1). */
        public int $oomKills = 0,

        /** `pids.events:max` — forks the kernel refused at the PID ceiling. */
        public int $pidLimitHits = 0,

        /**
         * 🛑 Whether the counters were readable at all.
         *
         * Zero and "not measured" are different facts and must not look
         * alike in a build record. Without the cgroup hierarchy mounted,
         * `oom_kills` and `pidLimitHits` are both 0 — and so a fork bomb
         * reports a clean build. That is how this field came to exist:
         * CI had no `/hostcg`, the sampler silently found nothing, and the
         * fork-bomb exit criterion passed as `succeeded`.
         */
        public bool $sampled = false,
    ) {}

    /**
     * 🛑 The highest reading wins when two samples are compared.
     *
     * The counters only ever rise, and the cgroup disappears at exit — so a
     * sample taken a moment too late reads zero from a missing file rather
     * than the real value. Keeping the maximum is what makes a poll that
     * raced the container's death harmless.
     */
    public function merge(self $other): self
    {
        return new self(
            oomKills: max($this->oomKills, $other->oomKills),
            pidLimitHits: max($this->pidLimitHits, $other->pidLimitHits),
            sampled: $this->sampled || $other->sampled,
        );
    }

    public function isClean(): bool
    {
        return $this->oomKills === 0 && $this->pidLimitHits === 0;
    }

    /** @return array<string, int> for the build record and `provenance.json`. */
    public function toArray(): array
    {
        return [
            'oom_kills' => $this->oomKills,
            'pid_limit_hits' => $this->pidLimitHits,
            'sampled' => $this->sampled ? 1 : 0,
        ];
    }
}
