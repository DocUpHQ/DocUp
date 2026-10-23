<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Providers;

use App\Builds\Runner\DockerRunnerDriver;
use App\Builds\Runner\RunnerDriver;
use App\Builds\Runner\Spool;
use Illuminate\Support\ServiceProvider;

/**
 * Binds the §8.5 pipeline and §11.4's `RunnerDriver`.
 *
 * 🛑 `app/Providers` is the one path the §8.5.13 architecture test allows to
 * name a runtime driver, for the same reason `ArtifactServiceProvider` is
 * allowed to name the artifact stores: binding a class is not calling it. The
 * exemption is by path rather than by a comment marker, so it cannot be
 * claimed by writing the right words in a file somewhere else.
 *
 * 🛑 Everything here must resolve **without a database**. The runner process
 * has no DB credentials at all (Phase 06's exit criterion), so a binding that
 * reached for a model or a config value out of the database would turn a
 * missing connection into a boot failure for the one process that is supposed
 * to work without one.
 */
final class BuildServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        /*
         * §11.4's seam: `runc | gvisor | kubernetes | external`. Phase 06
         * ships the first; §11.5's `scale` profile is a swap here and
         * nothing else, which is the whole reason the interface exists from
         * the first implementation rather than being extracted later.
         */
        $this->app->bind(RunnerDriver::class, DockerRunnerDriver::class);

        // A singleton so the worker and the runner cannot disagree about
        // where the spool is within one process.
        $this->app->singleton(Spool::class, static fn (): Spool => Spool::fromConfig());
    }
}
