<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Runner;

use App\Builds\RunSpecification;

/**
 * §11.4's `RunnerDriver` seam: `runc | gvisor | kubernetes | external`.
 *
 * Phase 06 ships the `runc` case, as a Docker CLI driver. The seam exists
 * from the first implementation rather than being extracted later because
 * §11.5's `scale` profile is a driver swap and nothing else — and a seam
 * introduced after three callers have grown around one implementation is a
 * refactor, not a seam.
 *
 * 🛑 Every method here is reachable **only** from the runner process. The
 * architecture test that enforces §8.5.13 asserts that nothing outside
 * `App\Builds\Runner` names a container runtime, which is what makes "the
 * runner is the sole holder" checkable rather than merely intended.
 */
interface RunnerDriver
{
    /**
     * Create the per-build workspace and return its name.
     *
     * 🛑 One per build, never shared. §8.5.20 forbids a writable shared cache
     * between builds because it is "a cross-tenant write channel and a
     * cache-poisoning surface"; a working tree is that argument with the
     * volume turned up, since it is the thing the generator reads.
     */
    public function createWorkspace(string $buildId): string;

    /**
     * Run one container to completion.
     *
     * @param  string|null  $credential  the git credential-helper body, piped
     *                                   into the container's stdin and
     *                                   nowhere else (§8.5.7). Only ever set
     *                                   for `fetch`, and
     *                                   {@see RunSpecification} refuses a
     *                                   specification that says otherwise.
     */
    public function run(RunSpecification $spec, ?string $credential = null): RunOutcome;

    /**
     * Export a directory from a workspace as an uncompressed tar.
     *
     * 🛑 This is what makes §8.21.6 true: "The built-in runner MUST be
     * implemented as the **first consumer** of this path, not a privileged
     * special case." The runner hands the worker a tarball, and the worker
     * publishes it through exactly the code an operator's CI reaches by
     * POSTing an archive. There is no second ingest path, so there is no
     * second set of validations to forget.
     *
     * @return bool false when the directory does not exist, which the caller
     *              reports as the §8.4.5 output-contract failure it is
     */
    public function exportDirectory(string $volume, string $containerPath, string $destinationTar): bool;

    /** Remove the workspace. Called whatever the outcome. */
    public function destroyWorkspace(string $volume): void;

    /** Remove containers a previous runner left behind. */
    public function sweep(): int;
}
