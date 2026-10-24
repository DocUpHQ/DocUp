<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Runner;

use App\Builds\BuildConfig;

/**
 * §8.5.15's authoritative resource signal, read from the kernel.
 *
 * > "OOM MUST be read authoritatively from cgroup `memory.events:oom_kill`"
 *
 * 🛑 **Measured in Phase 07: that file can only be read while the container
 * is alive.** A container's cgroup directory is removed when its init
 * exits, so there is no corpse to inspect — a read after the run finds
 * nothing, on both cgroup versions. The sampler is therefore polled from
 * the driver's existing output loop and the **last value seen** is what the
 * classification uses. Phase 06 read `State.OOMKilled` from the daemon
 * instead, which is the same kernel event surfaced second-hand; this is the
 * first-hand reading the specification asks for, and it carries two things
 * the daemon's boolean does not:
 *
 *  - a **count**, so "one child was killed" and "forty were" are different
 *    facts in the build record;
 *  - `pids.events:max`, which has no daemon equivalent at all. A fork bomb
 *    throttled by `--pids-limit` leaves `State.ExitCode` at 0 and
 *    `OOMKilled` false — the build looks successful while the kernel was
 *    refusing its forks. That counter is the only evidence it happened.
 *
 * 🛑 **Both cgroup versions, because the specification names only one.**
 * `memory.events` is cgroup v2. On v1 the same counter lives in
 * `memory.oom_control` as an `oom_kill` line (Linux 4.13+), and v1 is still
 * what Docker Desktop and several distributions present. Supporting one
 * would have meant the control silently not existing on the other, which is
 * worse than supporting both.
 */
final class CgroupSampler
{
    /** @param list<string> $memoryFiles */
    private function __construct(
        private readonly array $memoryFiles,
        private readonly ?string $pidsFile,
    ) {}

    /**
     * A sampler for a container, or null when the hierarchy is not visible.
     *
     * Null is a legitimate answer and the driver reports it as one: a runner
     * without the host cgroup hierarchy mounted cannot read these counters,
     * and claiming an authoritative reading we did not take would be worse
     * than saying so.
     */
    public static function forContainer(string $containerId): ?self
    {
        $root = BuildConfig::string('sandbox.cgroup_root', '');

        if ($root === '' || ! is_dir($root) || preg_match('/^[0-9a-f]{12,64}$/', $containerId) !== 1) {
            return null;
        }

        /*
         * Four layouts, probed in order. The first two are cgroup v2 under
         * the systemd and cgroupfs drivers; the last two are v1, where each
         * controller has its own hierarchy. Probing beats asking the daemon
         * for its driver: `docker info` reports the driver it was configured
         * with, and what matters is where the files actually are.
         */
        $candidates = [
            // cgroup v2, systemd driver
            [$root.'/system.slice/docker-'.$containerId.'.scope/memory.events',
                $root.'/system.slice/docker-'.$containerId.'.scope/pids.events'],
            // cgroup v2, cgroupfs driver
            [$root.'/docker/'.$containerId.'/memory.events',
                $root.'/docker/'.$containerId.'/pids.events'],
            // cgroup v1, cgroupfs driver
            [$root.'/memory/docker/'.$containerId.'/memory.oom_control',
                $root.'/pids/docker/'.$containerId.'/pids.events'],
            // cgroup v1, systemd driver
            [$root.'/memory/system.slice/docker-'.$containerId.'.scope/memory.oom_control',
                $root.'/pids/system.slice/docker-'.$containerId.'.scope/pids.events'],
        ];

        $memory = [];
        $pids = null;

        foreach ($candidates as [$memoryFile, $pidsFile]) {
            if (is_readable($memoryFile)) {
                $memory[] = $memoryFile;
                $pids ??= is_readable($pidsFile) ? $pidsFile : null;
            }
        }

        return $memory === [] && $pids === null ? null : new self($memory, $pids);
    }

    /**
     * The counters as they stand right now.
     *
     * 🛑 Never throws and never blocks. This runs inside the loop that reads
     * a container's output under §8.5.21's caps, and a sampler that could
     * raise would turn an unreadable file into a lost build log.
     */
    public function sample(): CgroupSample
    {
        return new CgroupSample(
            oomKills: $this->counter($this->memoryFiles, 'oom_kill'),
            pidLimitHits: $this->pidsFile === null ? 0 : $this->counter([$this->pidsFile], 'max'),
        );
    }

    /**
     * Read `<key> <n>` out of a `key value` file.
     *
     * The same shape serves `memory.events` (v2), `memory.oom_control` (v1)
     * and `pids.events` (both), which is why there is one reader rather than
     * three parsers.
     *
     * @param  list<string>  $files
     */
    private function counter(array $files, string $key): int
    {
        $total = 0;

        foreach ($files as $file) {
            $contents = @file_get_contents($file);

            if ($contents === false) {
                continue;
            }

            if (preg_match('/^'.preg_quote($key, '/').'\s+(\d+)$/m', $contents, $matches) === 1) {
                $total = max($total, (int) $matches[1]);
            }
        }

        return $total;
    }
}
