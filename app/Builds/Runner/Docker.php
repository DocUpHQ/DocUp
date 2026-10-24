<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Runner;

/**
 * One place that runs the container runtime's CLI, and the only place.
 *
 * 🛑 **`proc_open` with an argv array, never a shell.** `proc_open` given a
 * list executes the binary directly: no word splitting, no globbing, no
 * `$(...)`, no `;`. That is §8.5.13's "no code path from a webhook, a YAML
 * value or an HTTP request to an arbitrary runtime call" as code rather than
 * as a convention — a repository value spelled `; docker run --privileged`
 * arrives as a filename that does not exist.
 *
 * Extracted in Phase 07 because the warden, the cgroup sampler and the
 * §8.5.12 self-test all need it. The duplicate `proc_open` each of them
 * would otherwise have carried is exactly where the shell creeps back in:
 * the fourth copy is the one somebody writes with `exec()` because it was
 * shorter.
 */
final class Docker
{
    public function __construct(private readonly string $binary = 'docker') {}

    /**
     * Run a command and return its status and combined output.
     *
     * @param  list<string>  $argv  without the binary itself
     * @return array{0: int, 1: string}
     */
    public function capture(array $argv): array
    {
        $descriptors = [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open([$this->binary, ...$argv], $descriptors, $pipes);

        if (! is_resource($process)) {
            return [-1, ''];
        }

        $output = (string) stream_get_contents($pipes[1]);
        $output .= (string) stream_get_contents($pipes[2]);

        foreach ($pipes as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }

        return [proc_close($process), $output];
    }

    /** The binary itself, for the one caller that streams rather than captures. */
    public function binary(): string
    {
        return $this->binary;
    }
}
